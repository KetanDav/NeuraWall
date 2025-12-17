#!/usr/bin/env python3
"""
IDS Override API (runs on main NGFW box)

Endpoint:
    POST /ids_override
    JSON:
    {
      "flow_key": "192.168.100.11:5000-192.168.200.13:49376-TCP",
      "malicious": 0 or 1,
      "analyst_ip": "optional, will default to client IP"
    }

Behavior (malicious == 1):
- Look up flow in sessions.db (table sessions).
- Update decision fields:
    decision_action = "block"
    decision_label  = "malicious"
    decision_score  = 1.0
    decision_tier   = "ids_override"
    decision_reason = "ids malware sig matched (analyst_ip=...)"
- Treat ip_src as "sender", ip_dst as "receiver":
    - Call SOAR /block on sender IP
    - Call SOAR /quarantine on receiver IP

If malicious == 0:
- Mark as allowed with ids_override reason, no SOAR call.
"""

import time
import sqlite3
from pathlib import Path

from flask import Flask, request, jsonify
import requests

DB_FILE = "sessions.db"
SOAR_BASE = "http://localhost:6003"  # your SOAR API (block/quarantine) on main box

app = Flask(__name__)


# ─────────────────────────────
# DB helpers
# ─────────────────────────────

def get_conn() -> sqlite3.Connection:
    db_path = Path(DB_FILE)
    if not db_path.exists():
        raise SystemExit(f"[IDS_OVR] Database file {DB_FILE} not found")
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_session(conn: sqlite3.Connection, flow_key: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM sessions WHERE flow_key = ?", (flow_key,))
    return cur.fetchone()


def update_session_decision(
    conn: sqlite3.Connection,
    flow_key: str,
    action: str,
    label: str,
    score: float,
    tier: str,
    reason: str,
):
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE sessions
        SET
            decision_action = ?,
            decision_label  = ?,
            decision_score  = ?,
            decision_tier   = ?,
            decision_reason = ?
        WHERE flow_key = ?
        """,
        (action, label, score, tier, reason, flow_key),
    )
    conn.commit()
    print(f"[IDS_OVR] Updated decision for {flow_key}: {action}, reason={reason}")


# ─────────────────────────────
# SOAR helpers
# ─────────────────────────────

def call_soar_block(ip: str):
    try:
        r = requests.post(f"{SOAR_BASE}/block", json={"ip": ip}, timeout=2.0)
        if r.status_code != 200:
            return False, f"soar_block_http_{r.status_code}"
        data = r.json()
        return True, f"soar_block_ok_ticket={data.get('ticket_id', '?')}"
    except Exception as e:
        return False, f"soar_block_err_{e.__class__.__name__}"


def call_soar_quarantine(ip: str):
    try:
        r = requests.post(f"{SOAR_BASE}/quarantine", json={"ip": ip}, timeout=2.0)
        if r.status_code != 200:
            return False, f"soar_quar_http_{r.status_code}"
        data = r.json()
        return True, f"soar_quar_ok_ticket={data.get('ticket_id', '?')}"
    except Exception as e:
        return False, f"soar_quar_err_{e.__class__.__name__}"


# ─────────────────────────────
# API
# ─────────────────────────────

@app.route("/ids_override", methods=["POST"])
def ids_override():
    data = request.get_json(silent=True) or {}
    flow_key = data.get("flow_key")
    malicious = int(data.get("malicious", 0))
    analyst_ip = data.get("analyst_ip") or request.remote_addr

    if not flow_key:
        return jsonify({"status": "error", "message": "missing flow_key"}), 400

    conn = get_conn()
    row = fetch_session(conn, flow_key)
    if row is None:
        return jsonify({"status": "error", "message": f"flow_key not found: {flow_key}"}), 404

    ip_src = row["ip_src"]
    ip_dst = row["ip_dst"]

    result = {
        "flow_key": flow_key,
        "ip_src": ip_src,
        "ip_dst": ip_dst,
        "analyst_ip": analyst_ip,
        "malicious": malicious,
        "soar_block_sender": None,
        "soar_quarantine_receiver": None,
    }

    if malicious == 1:
        # Mark as malicious / blocked
        action = "block"
        label = "malicious"
        score = 1.0
        tier = "ids_override"
        reason = f"ids malware sig matched (analyst_ip={analyst_ip})"

        update_session_decision(conn, flow_key, action, label, score, tier, reason)

        # Sender = ip_src → block
        ok_b, info_b = call_soar_block(ip_src)
        result["soar_block_sender"] = {"ok": ok_b, "info": info_b}

        # Receiver = ip_dst → quarantine
        ok_q, info_q = call_soar_quarantine(ip_dst)
        result["soar_quarantine_receiver"] = {"ok": ok_q, "info": info_q}

        status = "malicious_blocked"
    else:
        # Mark as benign override
        action = "allow"
        label = "benign"
        score = 0.0
        tier = "ids_override"
        reason = f"ids override benign (analyst_ip={analyst_ip})"

        update_session_decision(conn, flow_key, action, label, score, tier, reason)
        status = "benign_allowed"

    result["status"] = status
    return jsonify(result), 200


if __name__ == "__main__":
    # Small API service on main box
    app.run(host="0.0.0.0", port=7000, debug=True)
