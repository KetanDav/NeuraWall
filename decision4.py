#!/usr/bin/env python3
"""
Decision Engine for AI-NGFW

Runs in a loop and, every ~30 seconds per active flow:

- Reads sessions from sessions.db (table: sessions)
- For each non-closed flow (unless locked by ids_override):
    * Calls anomaly model:
        GET http://localhost:5001/predict/<flow_key>
        -> { "label": 0/1, "prob_attack": float, "session_id": "..." }

    * Computes simple Threat Intel score from ti_metadata table

    * Computes endpoint agent score by pinging http://<internal_ip>:8080/

    * Generates IAM score randomly for now.

    * Merges scores into combined_score.

    * Updates sessions table:
        - anomaly_score, ti_score, endpoint_score, iam_score, combined_score
        - decision_action ("allow"/"block")
        - decision_label, decision_score, decision_tier, decision_reason
        - last_decision_ts (timestamp)

- If combined_score exceeds threshold and decision_action == "block":
    * Calls SOAR /block API:
        POST http://localhost:6003/block { "ip": "<chosen_ip>" }

NEW IMPORTANT BEHAVIOR:
- If a session already has decision_tier = 'ids_override' AND decision_action = 'block',
  this engine will SKIP that flow completely (manual override is treated as locked).
"""

import sqlite3
import time
import random
import requests
from pathlib import Path
from typing import Optional, Tuple

DB_FILE = "sessions.db"

ANOMALY_URL_TEMPLATE = "http://localhost:5001/predict/{flow_key}"
SOAR_BLOCK_URL = "http://localhost:6003/block"
DECISION_INTERVAL = 30.0

BLOCK_THRESHOLD = 0.8

W_ANOMALY = 0.4
W_TI = 0.3
W_ENDPOINT = 0.2
W_IAM = 0.1


# ─────────────────────────────────────────────
#  DB helpers
# ─────────────────────────────────────────────

def get_conn() -> sqlite3.Connection:
    db_path = Path(DB_FILE)
    if not db_path.exists():
        raise SystemExit(f"[DECISION] Database file {DB_FILE} not found. Run forwarder first.")
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [row[1] for row in cur.fetchall()]
    return column in cols


def ensure_extra_columns(conn: sqlite3.Connection):
    """
    Add decision-engine-specific columns to sessions IF they don't exist.
    """
    cur = conn.cursor()

    extra_cols = {
        "anomaly_score": "REAL",
        "ti_score": "REAL",
        "endpoint_score": "REAL",
        "iam_score": "REAL",
        "combined_score": "REAL",
        "last_decision_ts": "REAL",
    }

    for col, ctype in extra_cols.items():
        if not column_exists(conn, "sessions", col):
            print(f"[DECISION] Adding column sessions.{col} ({ctype})")
            cur.execute(f"ALTER TABLE sessions ADD COLUMN {col} {ctype}")

    conn.commit()


def fetch_active_sessions(conn: sqlite3.Connection):
    """
    Return all non-closed sessions.
    """
    cur = conn.cursor()
    cur.execute(
        """
        SELECT *
        FROM sessions
        WHERE state NOT LIKE 'CLOSED%'
           OR state IS NULL
        """
    )
    return cur.fetchall()


def fetch_ti_for_flow(conn: sqlite3.Connection, flow_key: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM ti_metadata WHERE flow_key = ?", (flow_key,))
        return cur.fetchone()
    except sqlite3.OperationalError:
        return None


def update_session_decision(
    conn: sqlite3.Connection,
    flow_key: str,
    anomaly_score: float,
    ti_score: float,
    endpoint_score: float,
    iam_score: float,
    combined_score: float,
    decision_action: str,
    decision_label: str,
    decision_tier: str,
    decision_reason: str,
    now_ts: float,
):
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE sessions
        SET
            anomaly_score   = ?,
            ti_score        = ?,
            endpoint_score  = ?,
            iam_score       = ?,
            combined_score  = ?,
            decision_action = ?,
            decision_label  = ?,
            decision_score  = ?,
            decision_tier   = ?,
            decision_reason = ?,
            last_decision_ts = ?
        WHERE flow_key = ?
        """,
        (
            anomaly_score,
            ti_score,
            endpoint_score,
            iam_score,
            combined_score,
            decision_action,
            decision_label,
            combined_score,
            decision_tier,
            decision_reason,
            now_ts,
            flow_key,
        ),
    )
    conn.commit()
    print(
        f"[DECISION] Updated {flow_key}: action={decision_action}, "
        f"score={combined_score:.3f}, reason={decision_reason}"
    )


# ─────────────────────────────────────────────
#  Scoring helpers
# ─────────────────────────────────────────────

def call_anomaly(flow_key: str) -> Tuple[float, str]:
    url = ANOMALY_URL_TEMPLATE.format(flow_key=flow_key)
    try:
        r = requests.get(url, timeout=0.5)
        if r.status_code != 200:
            return 0.0, f"anomaly_http_{r.status_code}"
        data = r.json()
        prob_attack = float(data.get("prob_attack", 0.0))
        label = data.get("label", 0)
        return prob_attack, f"anomaly_label={label}"
    except Exception as e:
        return 0.0, f"anomaly_error:{e.__class__.__name__}"


def compute_ti_score(ti_row: Optional[sqlite3.Row]) -> Tuple[float, str]:
    if ti_row is None:
        return 0.0, "ti_none"

    keys = ti_row.keys()
    http_host = ti_row["http_host"] if "http_host" in keys else None
    url = ti_row["url"] if "url" in keys else None
    tls_sni = ti_row["tls_sni"] if "tls_sni" in keys else None
    tls_ja3 = ti_row["tls_ja3"] if "tls_ja3" in keys else None

    score = 0.0
    reasons = []
    if http_host:
        score += 0.1
        reasons.append("host")
    if url:
        score += 0.1
        reasons.append("url")
    if tls_sni:
        score += 0.1
        reasons.append("sni")
    if tls_ja3:
        score += 0.1
        reasons.append("ja3")

    score = min(score, 0.4)
    reason = "ti_" + ",".join(reasons) if reasons else "ti_metadata_empty"
    return score, reason


def choose_internal_ip(ip_src: str, ip_dst: str) -> Optional[str]:
    def is_internal(ip: str) -> bool:
        return (
            ip.startswith("192.168.")
            or ip.startswith("10.")
            or ip.startswith("172.16.")
            or ip.startswith("172.17.")
            or ip.startswith("172.18.")
            or ip.startswith("172.19.")
            or ip.startswith("172.20.")
            or ip.startswith("172.21.")
            or ip.startswith("172.22.")
            or ip.startswith("172.23.")
            or ip.startswith("172.24.")
            or ip.startswith("172.25.")
            or ip.startswith("172.26.")
            or ip.startswith("172.27.")
            or ip.startswith("172.28.")
            or ip.startswith("172.29.")
            or ip.startswith("172.30.")
            or ip.startswith("172.31.")
        )

    preferred_prefix = "192.168.100."
    if ip_src.startswith(preferred_prefix):
        return ip_src
    if ip_dst.startswith(preferred_prefix):
        return ip_dst
    if is_internal(ip_src):
        return ip_src
    if is_internal(ip_dst):
        return ip_dst
    return ip_src or ip_dst or None


def compute_endpoint_score(ip_src: str, ip_dst: str) -> Tuple[float, str]:
    internal_ip = choose_internal_ip(ip_src, ip_dst)
    if not internal_ip:
        return 0.0, "endpoint_no_ip"

    url = f"http://{internal_ip}:8080/"
    try:
        r = requests.get(url, timeout=0.3)
        if r.status_code == 200:
            return 0.1, f"endpoint_ok:{internal_ip}"
        else:
            return 0.4, f"endpoint_http_{r.status_code}:{internal_ip}"
    except Exception as e:
        return 0.6, f"endpoint_unreachable:{internal_ip}:{e.__class__.__name__}"


def compute_iam_score() -> Tuple[float, str]:
    score = random.uniform(0.0, 0.5)
    return score, "iam_random"


def merge_scores(
    anomaly_score: float,
    ti_score: float,
    endpoint_score: float,
    iam_score: float,
) -> float:
    combined = (
        W_ANOMALY * anomaly_score +
        W_TI * ti_score +
        W_ENDPOINT * endpoint_score +
        W_IAM * iam_score
    )
    return max(0.0, min(combined, 1.0))


def decide_action(combined_score: float) -> str:
    if combined_score >= BLOCK_THRESHOLD:
        return "block"
    return "allow"


def build_reason(
    anomaly_info: str,
    ti_info: str,
    endpoint_info: str,
    iam_info: str,
    combined_score: float,
) -> str:
    return (
        f"combined={combined_score:.3f}; "
        f"{anomaly_info}; {ti_info}; {endpoint_info}; {iam_info}"
    )


# ─────────────────────────────────────────────
#  SOAR integration
# ─────────────────────────────────────────────

def call_soar_block(ip: str) -> Tuple[bool, str]:
    try:
        payload = {"ip": ip}
        r = requests.post(SOAR_BLOCK_URL, json=payload, timeout=1.0)
        if r.status_code != 200:
            return False, f"soar_http_{r.status_code}"
        data = r.json()
        return True, f"soar_block_ok_ticket={data.get('ticket_id', '?')}"
    except Exception as e:
        return False, f"soar_error:{e.__class__.__name__}"


def choose_ip_for_soar(ip_src: str, ip_dst: str) -> str:
    ip = choose_internal_ip(ip_src, ip_dst)
    return ip or ip_src or ip_dst


# ─────────────────────────────────────────────
#  Main loop
# ─────────────────────────────────────────────

def main_loop():
    conn = get_conn()
    ensure_extra_columns(conn)

    print("[DECISION] Decision engine started. Scanning flows every few seconds...")

    while True:
        now_ts = time.time()
        sessions = fetch_active_sessions(conn)

        for row in sessions:
            flow_key = row["flow_key"]
            state = row["state"] or ""
            ip_src = row["ip_src"]
            ip_dst = row["ip_dst"]

            # Skip closed sessions
            if state.startswith("CLOSED"):
                continue

            # 🔒 IMPORTANT: respect manual IDS override blocks
            existing_tier = row["decision_tier"] if "decision_tier" in row.keys() else None
            existing_action = row["decision_action"] if "decision_action" in row.keys() else None
            if existing_tier == "ids_override" and existing_action == "block":
                print(f"[DECISION] Skipping {flow_key}, locked by ids_override")
                continue

            last_dec_ts = row["last_decision_ts"] if "last_decision_ts" in row.keys() else None
            if last_dec_ts is not None and (now_ts - last_dec_ts) < DECISION_INTERVAL:
                continue

            print(f"[DECISION] Evaluating flow {flow_key}")

            anomaly_score, anomaly_info = call_anomaly(flow_key)

            ti_row = fetch_ti_for_flow(conn, flow_key)
            ti_score, ti_info = compute_ti_score(ti_row)

            endpoint_score, endpoint_info = compute_endpoint_score(ip_src, ip_dst)

            iam_score, iam_info = compute_iam_score()

            combined_score = merge_scores(
                anomaly_score,
                ti_score,
                endpoint_score,
                iam_score,
            )

            action = decide_action(combined_score)
            label = "decision_engine"
            tier = "decision_engine"

            reason = build_reason(
                anomaly_info,
                ti_info,
                endpoint_info,
                iam_info,
                combined_score,
            )

            update_session_decision(
                conn,
                flow_key,
                anomaly_score,
                ti_score,
                endpoint_score,
                iam_score,
                combined_score,
                action,
                label,
                tier,
                reason,
                now_ts,
            )

            if action == "block":
                ip_for_soar = choose_ip_for_soar(ip_src, ip_dst)
                if ip_for_soar:
                    ok, soar_info = call_soar_block(ip_for_soar)
                    print(
                        f"[DECISION] SOAR block for {ip_for_soar} "
                        f"from flow {flow_key}: {soar_info}"
                    )

        time.sleep(5.0)


if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\n[DECISION] Stopped by user.")
