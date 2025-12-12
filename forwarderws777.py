#!/usr/bin/env python3
"""
Inline NGFW engine between tap0 <-> tap1.

Responsibilities:
- Capture packets from tap0 and tap1 using AF_PACKET raw sockets
- Parse Ethernet / IPv4 / TCP
- Maintain per-flow sessions
- Extract basic L3/L4 stats and light L7 hints (HTTP/TLS)
- Send first 10 packets of a flow to the appropriate classifier endpoint:
    - /fastclassify-plain
    - /fastclassify-encrypted
    - /fastclassify-normal
- Apply classifier decision (allow/block)
- Log sessions, features, TI metadata, SOAR actions into SQLite
"""

import socket
import select
import sys
import time
import struct
import requests
import base64
import sqlite3
import hashlib

# --------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------

ETH_P_ALL = 0x0003

LOG_FILE = "tap0_tap1_inline_fast.log"
DB_FILE = "sessions.db"

# Three different classifier endpoints (you said: Option B)
CLASSIFIER_PLAIN_URL = "http://127.0.0.1:5000/fastclassify-plain"
CLASSIFIER_ENC_URL   = "http://127.0.0.1:5000/fastclassify-encrypted"
CLASSIFIER_L4_URL    = "http://127.0.0.1:5000/fastclassify-normal"

# Session table in memory
SESS = {}
DB_CONN = None


# --------------------------------------------------------------------
# DB initialization
# --------------------------------------------------------------------

def init_db():
    """
    Initialize SQLite database with:
    - sessions: per-flow summary + ML decision
    - flow_features: rolling 30s window stats
    - ti_metadata: HTTP/TLS intel
    - access_control: IP blocklist
    - soar_actions: action logs
    """
    global DB_CONN
    DB_CONN = sqlite3.connect(DB_FILE)
    c = DB_CONN.cursor()

    # Reset volatile tables
    c.execute("DROP TABLE IF EXISTS sessions")
    c.execute("DROP TABLE IF EXISTS flow_features")
    c.execute("DROP TABLE IF EXISTS ti_metadata")

    c.execute(
        """
        CREATE TABLE sessions (
            flow_key TEXT PRIMARY KEY,
            ip_src TEXT,
            ip_dst TEXT,
            sport INTEGER,
            dport INTEGER,
            proto INTEGER,
            first_ts REAL,
            last_ts REAL,
            dur REAL,
            pkt_count INTEGER,
            pkts_fwd INTEGER,
            pkts_rev INTEGER,
            bytes_fwd INTEGER,
            bytes_rev INTEGER,
            sbytes INTEGER,
            dbytes INTEGER,
            sttl INTEGER,
            dttl INTEGER,
            Spkts INTEGER,
            Dpkts INTEGER,
            swin INTEGER,
            dwin INTEGER,
            stcpb INTEGER,
            dtcpb INTEGER,
            smeansz REAL,
            dmeansz REAL,
            Sintpkt REAL,
            Dintpkt REAL,
            state TEXT,
            is_sm_ips_ports INTEGER,
            syn_count INTEGER,
            fin_count INTEGER,
            rst_count INTEGER,
            decision_action TEXT,
            decision_label TEXT,
            decision_score REAL,
            decision_tier TEXT,
            decision_reason TEXT
        )
        """
    )

    c.execute(
        """
        CREATE TABLE flow_features (
            flow_key TEXT PRIMARY KEY,
            sport INTEGER,
            dsport INTEGER,
            proto INTEGER,
            state TEXT,
            dur REAL,
            sbytes INTEGER,
            dbytes INTEGER,
            sttl INTEGER,
            dttl INTEGER,
            Spkts INTEGER,
            Dpkts INTEGER,
            swin INTEGER,
            dwin INTEGER,
            stcpb INTEGER,
            dtcpb INTEGER,
            smeansz REAL,
            dmeansz REAL,
            Sintpkt REAL,
            Dintpkt REAL,
            Stime REAL,
            Ltime REAL,
            is_sm_ips_ports INTEGER
        )
        """
    )

    c.execute(
        """
        CREATE TABLE ti_metadata (
            flow_key TEXT PRIMARY KEY,
            ip_src TEXT,
            ip_dst TEXT,
            sport INTEGER,
            dport INTEGER,
            proto INTEGER,
            http_host TEXT,
            http_path TEXT,
            url TEXT,
            tls_ja3 TEXT,
            tls_sni TEXT
        )
        """
    )

    # Persistent tables for manual control / SOAR history
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS access_control (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            action TEXT,
            reason TEXT,
            created_at REAL,
            expires_at REAL
        )
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS soar_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       REAL,
            flow_key TEXT,
            ip_src   TEXT,
            ip_dst   TEXT,
            sport    INTEGER,
            dport    INTEGER,
            proto    INTEGER,
            state    TEXT,
            sbytes   INTEGER,
            dbytes   INTEGER,
            Spkts    INTEGER,
            Dpkts    INTEGER,
            action   TEXT,
            label    TEXT,
            score    REAL,
            tier     TEXT,
            reason   TEXT,
            source   TEXT
        )
        """
    )

    DB_CONN.commit()
    print(f"[DEBUG] SQLite DB initialized at {DB_FILE}")


# --------------------------------------------------------------------
# Session / feature persistence helpers
# --------------------------------------------------------------------

def compute_flow_stats(sess):
    """
    Compute per-flow summary stats used in sessions + ML features.
    """
    Stime = sess["first_ts"]
    Ltime = sess["last_ts"]
    dur = max(Ltime - Stime, 0.0)

    sbytes = sess["sbytes"]
    dbytes = sess["dbytes"]
    Spkts = sess["pkts_fwd"]
    Dpkts = sess["pkts_rev"]

    sttl = sess["sttl"] if sess["sttl"] is not None else 0
    dttl = sess["dttl"] if sess["dttl"] is not None else 0
    swin = sess["swin"] if sess["swin"] is not None else 0
    dwin = sess["dwin"] if sess["dwin"] is not None else 0
    stcpb = sess["stcpb"] if sess["stcpb"] is not None else 0
    dtcpb = sess["dtcpb"] if sess["dtcpb"] is not None else 0

    smeansz = float(sbytes) / Spkts if Spkts > 0 else 0.0
    dmeansz = float(dbytes) / Dpkts if Dpkts > 0 else 0.0

    fwd_ts = [e[0] for e in sess["events_all"] if e[1]]
    rev_ts = [e[0] for e in sess["events_all"] if not e[1]]

    def mean_inter_arrival(ts_list):
        if len(ts_list) < 2:
            return 0.0
        diffs = [ts_list[i] - ts_list[i - 1] for i in range(1, len(ts_list))]
        return sum(diffs) / float(len(diffs))

    Sintpkt = mean_inter_arrival(fwd_ts)
    Dintpkt = mean_inter_arrival(rev_ts)

    is_sm_ips_ports = 1 if (sess["ip_src"] == sess["ip_dst"] or sess["sport"] == sess["dport"]) else 0

    return {
        "dur": dur,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "sttl": sttl,
        "dttl": dttl,
        "Spkts": Spkts,
        "Dpkts": Dpkts,
        "swin": swin,
        "dwin": dwin,
        "stcpb": stcpb,
        "dtcpb": dtcpb,
        "smeansz": smeansz,
        "dmeansz": dmeansz,
        "Sintpkt": Sintpkt,
        "Dintpkt": Dintpkt,
        "is_sm_ips_ports": is_sm_ips_ports,
    }


def upsert_session(sess):
    """
    Insert or update a row in `sessions` for this flow.
    """
    if DB_CONN is None:
        return

    feats = compute_flow_stats(sess)
    c = DB_CONN.cursor()
    c.execute(
        """
        INSERT INTO sessions (
            flow_key, ip_src, ip_dst, sport, dport, proto,
            first_ts, last_ts, dur,
            pkt_count, pkts_fwd, pkts_rev,
            bytes_fwd, bytes_rev,
            sbytes, dbytes,
            sttl, dttl,
            Spkts, Dpkts,
            swin, dwin,
            stcpb, dtcpb,
            smeansz, dmeansz,
            Sintpkt, Dintpkt,
            state, is_sm_ips_ports,
            syn_count, fin_count, rst_count,
            decision_action, decision_label, decision_score, decision_tier, decision_reason
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(flow_key) DO UPDATE SET
            ip_src=excluded.ip_src,
            ip_dst=excluded.ip_dst,
            sport=excluded.sport,
            dport=excluded.dport,
            proto=excluded.proto,
            first_ts=excluded.first_ts,
            last_ts=excluded.last_ts,
            dur=excluded.dur,
            pkt_count=excluded.pkt_count,
            pkts_fwd=excluded.pkts_fwd,
            pkts_rev=excluded.pkts_rev,
            bytes_fwd=excluded.bytes_fwd,
            bytes_rev=excluded.bytes_rev,
            sbytes=excluded.sbytes,
            dbytes=excluded.dbytes,
            sttl=excluded.sttl,
            dttl=excluded.dttl,
            Spkts=excluded.Spkts,
            Dpkts=excluded.Dpkts,
            swin=excluded.swin,
            dwin=excluded.dwin,
            stcpb=excluded.stcpb,
            dtcpb=excluded.dtcpb,
            smeansz=excluded.smeansz,
            dmeansz=excluded.dmeansz,
            Sintpkt=excluded.Sintpkt,
            Dintpkt=excluded.Dintpkt,
            state=excluded.state,
            is_sm_ips_ports=excluded.is_sm_ips_ports,
            syn_count=excluded.syn_count,
            fin_count=excluded.fin_count,
            rst_count=excluded.rst_count,
            decision_action=excluded.decision_action,
            decision_label=excluded.decision_label,
            decision_score=excluded.decision_score,
            decision_tier=excluded.decision_tier,
            decision_reason=excluded.decision_reason
        """,
        (
            sess["key"],
            sess["ip_src"],
            sess["ip_dst"],
            sess["sport"],
            sess["dport"],
            sess["proto"],
            sess["first_ts"],
            sess["last_ts"],
            feats["dur"],
            sess["pkt_count"],
            sess["pkts_fwd"],
            sess["pkts_rev"],
            sess["bytes_fwd"],
            sess["bytes_rev"],
            feats["sbytes"],
            feats["dbytes"],
            feats["sttl"],
            feats["dttl"],
            feats["Spkts"],
            feats["Dpkts"],
            feats["swin"],
            feats["dwin"],
            feats["stcpb"],
            feats["dtcpb"],
            feats["smeansz"],
            feats["dmeansz"],
            feats["Sintpkt"],
            feats["Dintpkt"],
            sess["conn_state"],
            feats["is_sm_ips_ports"],
            sess["syn_count"],
            sess["fin_count"],
            sess["rst_count"],
            sess["decision_action"],
            sess["decision_label"],
            sess["decision_score"],
            sess["decision_tier"],
            sess["decision_reason"],
        ),
    )
    DB_CONN.commit()
    upsert_ti_metadata(sess)
    print(f"[DEBUG] Upserted session in DB: {sess['key']}")


def upsert_flow_features(sess, feats_win):
    """
    Persist rolling 30-second window features for the flow.
    """
    if DB_CONN is None:
        return
    c = DB_CONN.cursor()
    c.execute(
        """
        INSERT INTO flow_features (
            flow_key,
            sport, dsport, proto, state,
            dur,
            sbytes, dbytes,
            sttl, dttl,
            Spkts, Dpkts,
            swin, dwin,
            stcpb, dtcpb,
            smeansz, dmeansz,
            Sintpkt, Dintpkt,
            Stime, Ltime,
            is_sm_ips_ports
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(flow_key) DO UPDATE SET
            sport=excluded.sport,
            dsport=excluded.dsport,
            proto=excluded.proto,
            state=excluded.state,
            dur=excluded.dur,
            sbytes=excluded.sbytes,
            dbytes=excluded.dbytes,
            sttl=excluded.sttl,
            dttl=excluded.dttl,
            Spkts=excluded.Spkts,
            Dpkts=excluded.Dpkts,
            swin=excluded.swin,
            dwin=excluded.dwin,
            stcpb=excluded.stcpb,
            dtcpb=excluded.dtcpb,
            smeansz=excluded.smeansz,
            dmeansz=excluded.dmeansz,
            Sintpkt=excluded.Sintpkt,
            Dintpkt=excluded.Dintpkt,
            Stime=excluded.Stime,
            Ltime=excluded.Ltime,
            is_sm_ips_ports=excluded.is_sm_ips_ports
        """,
        (
            sess["key"],
            sess["sport"],
            sess["dport"],
            sess["proto"],
            sess["conn_state"],
            feats_win["dur"],
            feats_win["sbytes"],
            feats_win["dbytes"],
            feats_win["sttl"],
            feats_win["dttl"],
            feats_win["Spkts"],
            feats_win["Dpkts"],
            feats_win["swin"],
            feats_win["dwin"],
            feats_win["stcpb"],
            feats_win["dtcpb"],
            feats_win["smeansz"],
            feats_win["dmeansz"],
            feats_win["Sintpkt"],
            feats_win["Dintpkt"],
            feats_win["Stime"],
            feats_win["Ltime"],
            feats_win["is_sm_ips_ports"],
        ),
    )
    DB_CONN.commit()
    print(f"[DEBUG] Upserted flow_features (30s window) for: {sess['key']}")


def upsert_ti_metadata(sess):
    """
    Insert/update HTTP/TLS metadata for the flow.
    """
    if DB_CONN is None:
        return
    c = DB_CONN.cursor()
    http_host = sess.get("http_host")
    http_path = sess.get("http_path")
    url = f"http://{http_host}{http_path}" if http_host and http_path else None
    tls_ja3 = sess.get("tls_ja3")
    tls_sni = sess.get("tls_sni")
    try:
        c.execute(
            """
            INSERT INTO ti_metadata (
                flow_key,
                ip_src, ip_dst,
                sport, dport, proto,
                http_host, http_path, url,
                tls_ja3, tls_sni
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(flow_key) DO UPDATE SET
                ip_src=excluded.ip_src,
                ip_dst=excluded.ip_dst,
                sport=excluded.sport,
                dport=excluded.dport,
                proto=excluded.proto,
                http_host=COALESCE(excluded.http_host, http_host),
                http_path=COALESCE(excluded.http_path, http_path),
                url=COALESCE(excluded.url, url),
                tls_ja3=COALESCE(excluded.tls_ja3, tls_ja3),
                tls_sni=COALESCE(excluded.tls_sni, tls_sni)
            """,
            (
                sess["key"],
                sess["ip_src"],
                sess["ip_dst"],
                sess["sport"],
                sess["dport"],
                sess["proto"],
                http_host,
                http_path,
                url,
                tls_ja3,
                tls_sni,
            ),
        )
        DB_CONN.commit()
        print(f"[DEBUG] Upserted TI metadata for: {sess['key']}")
    except Exception as e:
        print(f"[DEBUG] TI metadata upsert error for {sess['key']}: {e}")


# --------------------------------------------------------------------
# Low-level parsing helpers
# --------------------------------------------------------------------

def open_iface(ifname: str):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((ifname, 0))
    print(f"[DEBUG] Opened raw socket on {ifname}")
    return s


def mac_to_str(mac_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac_bytes)


def parse_eth_header(frame: bytes):
    if len(frame) < 14:
        print("[DEBUG] Frame too short for Ethernet header")
        return None
    dst_mac = mac_to_str(frame[0:6])
    src_mac = mac_to_str(frame[6:12])
    ethertype = int.from_bytes(frame[12:14], "big")
    return {"dst_mac": dst_mac, "src_mac": src_mac, "ethertype": ethertype}


def ip_to_str(ip_bytes: bytes) -> str:
    return ".".join(str(b) for b in ip_bytes)


def parse_ipv4_header(frame: bytes, offset: int = 14):
    if len(frame) < offset + 20:
        print("[DEBUG] Frame too short for IPv4 header")
        return None
    ip_header = frame[offset:offset + 20]
    ver_ihl, tos, total_length, ident, flags_frag, ttl, proto, checksum, src, dst = struct.unpack(
        "!BBHHHBBH4s4s", ip_header
    )
    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F
    ip_header_len = ihl * 4
    if len(frame) < offset + ip_header_len:
        print("[DEBUG] Frame shorter than full IPv4 header length")
        return None
    return {
        "version": version,
        "ihl": ihl,
        "tos": tos,
        "total_length": total_length,
        "id": ident,
        "flags_frag": flags_frag,
        "ttl": ttl,
        "protocol": proto,
        "checksum": checksum,
        "src_ip": ip_to_str(src),
        "dst_ip": ip_to_str(dst),
        "header_len_bytes": ip_header_len,
        "total_length": total_length,
    }


def parse_tcp_header(frame: bytes, offset: int):
    if len(frame) < offset + 20:
        print("[DEBUG] Frame too short for TCP header")
        return None
    tcp_header = frame[offset:offset + 20]
    src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urg_ptr = struct.unpack(
        "!HHLLHHHH", tcp_header
    )
    data_offset = (offset_reserved_flags >> 12) & 0xF
    flags = offset_reserved_flags & 0x3F
    names = []
    if flags & 0x01:
        names.append("FIN")
    if flags & 0x02:
        names.append("SYN")
    if flags & 0x04:
        names.append("RST")
    if flags & 0x08:
        names.append("PSH")
    if flags & 0x10:
        names.append("ACK")
    if flags & 0x20:
        names.append("URG")
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "data_offset": data_offset,
        "window": window,
        "checksum": checksum,
        "urg_ptr": urg_ptr,
        "flags": ",".join(names) if names else "NONE",
    }


def make_flow_key(ip: dict, tcp: dict, proto_name="TCP"):
    """
    Normalize flow key so both directions map to same key.
    """
    a = (ip["src_ip"], tcp["src_port"])
    b = (ip["dst_ip"], tcp["dst_port"])
    if a <= b:
        ip1, p1 = a
        ip2, p2 = b
    else:
        ip1, p1 = b
        ip2, p2 = a
    return f"{ip1}:{p1}-{ip2}:{p2}-{proto_name}"


def compute_payload_len(ip, tcp):
    total_len = ip["total_length"]
    ip_hlen = ip["header_len_bytes"]
    tcp_hlen = tcp["data_offset"] * 4
    payload_len = total_len - ip_hlen - tcp_hlen
    return payload_len if payload_len > 0 else 0


# --------------------------------------------------------------------
# L7 helpers: HTTP / TLS
# --------------------------------------------------------------------

def try_parse_http_request(payload: bytes):
    """
    Very simple HTTP request parser: method + path + host.
    """
    try:
        header_blob = payload.split(b"\r\n\r\n", 1)[0]
        lines = header_blob.split(b"\r\n")
        if not lines:
            return None
        request_line = lines[0].decode(errors="ignore")
        parts = request_line.split(" ")
        if len(parts) < 2:
            return None
        method = parts[0]
        path = parts[1]
        if method not in ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"):
            return None
        host = None
        for line in lines[1:]:
            if line.lower().startswith(b"host:"):
                host = line.split(b":", 1)[1].strip().decode(errors="ignore")
                break
        return {"method": method, "path": path, "host": host}
    except Exception:
        return None


def try_parse_tls_client_hello(payload: bytes):
    """
    Lightweight TLS ClientHello parser to extract:
    - pseudo-JA3 hash (md5 of first 64 bytes)
    - SNI hostname (if present)
    """
    if len(payload) < 11:
        return None
    if payload[0] != 0x16:  # Handshake record
        return None
    if payload[5] != 0x01:  # ClientHello
        return None
    ja3 = hashlib.md5(payload[:64]).hexdigest()
    sni_host = None
    try:
        idx = 5
        handshake_type = payload[idx]
        idx += 1
        length = int.from_bytes(payload[idx:idx+3], "big")  # noqa: F841  (not used)
        idx += 3
        idx += 2           # client_version
        idx += 32          # random
        sid_len = payload[idx]
        idx += 1 + sid_len
        cs_len = int.from_bytes(payload[idx:idx+2], "big")
        idx += 2 + cs_len
        comp_len = payload[idx]
        idx += 1 + comp_len
        if idx + 2 > len(payload):
            return {"ja3": ja3, "sni": None}
        ext_len = int.from_bytes(payload[idx:idx+2], "big")
        idx += 2
        end_ext = min(len(payload), idx + ext_len)
        while idx + 4 <= end_ext:
            etype = int.from_bytes(payload[idx:idx+2], "big")
            e_len = int.from_bytes(payload[idx+2:idx+4], "big")
            idx += 4
            if idx + e_len > end_ext:
                break
            edata = payload[idx:idx+e_len]
            idx += e_len
            if etype == 0 and e_len >= 5:  # server_name extension
                list_len = int.from_bytes(edata[0:2], "big")  # noqa: F841
                pos = 2
                if pos + 3 <= len(edata):
                    name_type = edata[pos]                   # noqa: F841
                    host_len = int.from_bytes(edata[pos+1:pos+3], "big")
                    pos += 3
                    if pos + host_len <= len(edata):
                        sni_host = edata[pos:pos+host_len].decode(errors="ignore")
                        break
        return {"ja3": ja3, "sni": sni_host}
    except Exception:
        return {"ja3": ja3, "sni": None}


# --------------------------------------------------------------------
# TCP state machine
# --------------------------------------------------------------------

def update_conn_state(sess, flags_str):
    old = sess["conn_state"]
    if "RST" in flags_str:
        sess["conn_state"] = "CLOSED_RST"
    elif "FIN" in flags_str:
        if sess["conn_state"] in ("ESTABLISHED", "FIN_WAIT"):
            sess["conn_state"] = "CLOSED_FIN"
        else:
            sess["conn_state"] = "FIN_WAIT"
    elif "SYN" in flags_str and "ACK" not in flags_str:
        if sess["conn_state"] == "NEW":
            sess["conn_state"] = "SYN_SENT"
    elif "SYN" in flags_str and "ACK" in flags_str:
        if sess["conn_state"] in ("NEW", "SYN_SENT"):
            sess["conn_state"] = "SYN_RECV"
    elif "ACK" in flags_str:
        if sess["conn_state"] in ("SYN_SENT", "SYN_RECV", "NEW"):
            sess["conn_state"] = "ESTABLISHED"
    if old != sess["conn_state"]:
        print(f"[DEBUG] Flow {sess['key']} state changed {old} -> {sess['conn_state']}")


# --------------------------------------------------------------------
# Session creation / update
# --------------------------------------------------------------------

def new_session(key, ip, tcp, now):
    """
    Initialize a new per-flow session dict with all fields.
    """
    return {
        "key": key,
        "ip_src": ip["src_ip"],
        "ip_dst": ip["dst_ip"],
        "sport": tcp["src_port"],
        "dport": tcp["dst_port"],
        "proto": ip["protocol"],
        "first_ts": now,
        "last_ts": now,

        "pkt_count": 0,
        "pkts_fwd": 0,
        "pkts_rev": 0,
        "bytes_fwd": 0,
        "bytes_rev": 0,

        "sbytes": 0,
        "dbytes": 0,
        "sttl": None,
        "dttl": None,
        "swin": None,
        "dwin": None,
        "stcpb": None,
        "dtcpb": None,

        "syn_count": 0,
        "fin_count": 0,
        "rst_count": 0,

        "captured_packets": [],
        "sent_for_classification": False,

        "decision_action": None,
        "decision_label": None,
        "decision_score": None,
        "decision_tier": None,
        "decision_reason": None,

        "events_all": [],
        "events_win": [],

        "conn_state": "NEW",

        # L7 metadata
        "http_host": None,
        "http_path": None,
        "http_method": None,

        "tls_ja3": None,
        "tls_sni": None,

        # L7 detection flags (for model choice)
        "seen_http": False,
        "seen_ftp": False,
        "seen_dns": False,
        "seen_telnet": False,
        "seen_tls": False,
        "seen_ssh": False,

        # Direction of first packet (0 = src->dst as created, 1 = reverse)
        "first_dir": None,

        # SOAR / access control
        "is_blocklisted": None,
        "soar_block_logged": False,
    }


def update_session(ip, tcp, frame, payload, now):
    """
    Update session stats with a new packet.
    """
    key = make_flow_key(ip, tcp, "TCP")
    sess = SESS.get(key)
    if sess is None:
        sess = new_session(key, ip, tcp, now)
        SESS[key] = sess
        print(f"[DEBUG] New session created: {key}")

    sess["last_ts"] = now
    sess["pkt_count"] += 1

    payload_len = compute_payload_len(ip, tcp)
    dir_is_fwd = (ip["src_ip"] == sess["ip_src"])
    if sess["first_dir"] is None:
        sess["first_dir"] = 0 if dir_is_fwd else 1

    flags_str = tcp["flags"]

    # Directional counters
    if dir_is_fwd:
        sess["pkts_fwd"] += 1
        sess["bytes_fwd"] += payload_len
        sess["sbytes"] += payload_len
        if sess["sttl"] is None:
            sess["sttl"] = ip["ttl"]
        sess["swin"] = tcp["window"]
        if sess["stcpb"] is None:
            sess["stcpb"] = tcp["seq"]
    else:
        sess["pkts_rev"] += 1
        sess["bytes_rev"] += payload_len
        sess["dbytes"] += payload_len
        if sess["dttl"] is None:
            sess["dttl"] = ip["ttl"]
        sess["dwin"] = tcp["window"]
        if sess["dtcpb"] is None:
            sess["dtcpb"] = tcp["seq"]

    # Flag counters
    if "SYN" in flags_str:
        sess["syn_count"] += 1
    if "FIN" in flags_str:
        sess["fin_count"] += 1
    if "RST" in flags_str:
        sess["rst_count"] += 1

    update_conn_state(sess, flags_str)

    # Window events
    sess["events_all"].append((now, dir_is_fwd, payload_len))
    sess["events_win"].append((now, dir_is_fwd, payload_len,
                               "SYN" in flags_str, "FIN" in flags_str, "RST" in flags_str))

    # Light L7 parsing (only for forward direction payloads)
    if dir_is_fwd and payload_len > 0:
        # HTTP on common ports
        if tcp["dst_port"] in (80, 8080, 8000, 8001):
            http = try_parse_http_request(payload)
            if http is not None:
                sess["http_host"] = http.get("host")
                sess["http_path"] = http.get("path")
                sess["http_method"] = http.get("method")
                sess["seen_http"] = True
                print(f"[DEBUG] Parsed HTTP for {key}: method={sess['http_method']} host={sess['http_host']} path={sess['http_path']}")

        # TLS on typical ports
        if tcp["dst_port"] in (443, 8443):
            tls = try_parse_tls_client_hello(payload)
            if tls is not None:
                sess["tls_ja3"] = tls.get("ja3")
                sess["tls_sni"] = tls.get("sni")
                sess["seen_tls"] = True
                print(f"[DEBUG] Parsed TLS for {key}: ja3={sess['tls_ja3']} sni={sess['tls_sni']}")

        # Simple port-based flags for other protocols (no deep parsing yet)
        if tcp["dst_port"] == 21:
            sess["seen_ftp"] = True
        if tcp["dst_port"] == 23:
            sess["seen_telnet"] = True
        if tcp["dst_port"] == 53:
            sess["seen_dns"] = True
        if tcp["dst_port"] == 22:
            sess["seen_ssh"] = True

    # Capture first 10 full frames for ML
    if sess["pkt_count"] <= 10:
        sess["captured_packets"].append(frame)
        print(f"[DEBUG] Captured packet {sess['pkt_count']} for flow {key}")
    else:
        print(f"[DEBUG] Packet {sess['pkt_count']} for existing flow {key}")

    return key, sess


def update_flow_window(sess, now, window_seconds=30.0):
    """
    Maintain the last `window_seconds` worth of per-packet events
    and persist into flow_features.
    """
    events = sess["events_win"]
    cutoff = now - window_seconds
    new_events = [e for e in events if e[0] >= cutoff]
    sess["events_win"] = new_events

    if not new_events:
        feats_win = {
            "dur": 0.0,
            "sbytes": 0,
            "dbytes": 0,
            "sttl": sess["sttl"] if sess["sttl"] is not None else 0,
            "dttl": sess["dttl"] if sess["dttl"] is not None else 0,
            "Spkts": 0,
            "Dpkts": 0,
            "swin": sess["swin"] if sess["swin"] is not None else 0,
            "dwin": sess["dwin"] if sess["dwin"] is not None else 0,
            "stcpb": sess["stcpb"] if sess["stcpb"] is not None else 0,
            "dtcpb": sess["dtcpb"] if sess["dtcpb"] is not None else 0,
            "smeansz": 0.0,
            "dmeansz": 0.0,
            "Sintpkt": 0.0,
            "Dintpkt": 0.0,
            "Stime": now,
            "Ltime": now,
            "is_sm_ips_ports": 1 if (sess["ip_src"] == sess["ip_dst"] or sess["sport"] == sess["dport"]) else 0,
        }
        upsert_flow_features(sess, feats_win)
        return

    sbytes = 0
    dbytes = 0
    Spkts = 0
    Dpkts = 0
    fwd_ts = []
    rev_ts = []

    for ts, dir_is_fwd, length, is_syn, is_fin, is_rst in new_events:
        if dir_is_fwd:
            Spkts += 1
            sbytes += length
            fwd_ts.append(ts)
        else:
            Dpkts += 1
            dbytes += length
            rev_ts.append(ts)

    Stime = min(e[0] for e in new_events)
    Ltime = max(e[0] for e in new_events)
    dur = max(Ltime - Stime, 0.0)

    smeansz = float(sbytes) / Spkts if Spkts > 0 else 0.0
    dmeansz = float(dbytes) / Dpkts if Dpkts > 0 else 0.0

    def mean_inter_arrival(ts_list):
        if len(ts_list) < 2:
            return 0.0
        diffs = [ts_list[i] - ts_list[i - 1] for i in range(1, len(ts_list))]
        return sum(diffs) / float(len(diffs))

    Sintpkt = mean_inter_arrival(fwd_ts)
    Dintpkt = mean_inter_arrival(rev_ts)

    sttl = sess["sttl"] if sess["sttl"] is not None else 0
    dttl = sess["dttl"] if sess["dttl"] is not None else 0
    swin = sess["swin"] if sess["swin"] is not None else 0
    dwin = sess["dwin"] if sess["dwin"] is not None else 0
    stcpb = sess["stcpb"] if sess["stcpb"] is not None else 0
    dtcpb = sess["dtcpb"] if sess["dtcpb"] is not None else 0
    is_sm_ips_ports = 1 if (sess["ip_src"] == sess["ip_dst"] or sess["sport"] == sess["dport"]) else 0

    feats_win = {
        "dur": dur,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "sttl": sttl,
        "dttl": dttl,
        "Spkts": Spkts,
        "Dpkts": Dpkts,
        "swin": swin,
        "dwin": dwin,
        "stcpb": stcpb,
        "dtcpb": dtcpb,
        "smeansz": smeansz,
        "dmeansz": dmeansz,
        "Sintpkt": Sintpkt,
        "Dintpkt": Dintpkt,
        "Stime": Stime,
        "Ltime": Ltime,
        "is_sm_ips_ports": is_sm_ips_ports,
    }

    upsert_flow_features(sess, feats_win)


# --------------------------------------------------------------------
# Classifier integration
# --------------------------------------------------------------------

def choose_model_for_flow(sess):
    """
    Decide which classifier to call based on L7 hints.
    - If we saw HTTP/FTP/DNS/Telnet → plaintext model
    - If we saw TLS/SSH indicators   → encrypted model
    - Otherwise                      → generic L4 model
    """
    if sess.get("seen_http") or sess.get("seen_ftp") or sess.get("seen_dns") or sess.get("seen_telnet"):
        return "plain"
    if sess.get("seen_tls") or sess.get("seen_ssh") or sess.get("tls_ja3") or sess.get("tls_sni"):
        return "encrypted"
    return "l4"


def classifier_url_for(kind: str) -> str:
    if kind == "plain":
        return CLASSIFIER_PLAIN_URL
    if kind == "encrypted":
        return CLASSIFIER_ENC_URL
    return CLASSIFIER_L4_URL


def send_for_classification(sess):
    """
    Send first up-to-10 raw packets + basic metadata to appropriate classifier.
    Only called once per flow (when pkt_count >= 10).
    """
    if sess["sent_for_classification"]:
        print(f"[DEBUG] Session {sess['key']} already sent for classification, skipping")
        return

    model_kind = choose_model_for_flow(sess)
    url = classifier_url_for(model_kind)

    print(
        f"[DEBUG] Sending {len(sess['captured_packets'])} packets for classification "
        f"for flow {sess['key']} using model={model_kind} url={url}"
    )

    packets_b64 = [base64.b64encode(p).decode("ascii") for p in sess["captured_packets"]]
    body = {
        "flow_key": sess["key"],
        "ip_src": sess["ip_src"],
        "ip_dst": sess["ip_dst"],
        "sport": sess["sport"],
        "dport": sess["dport"],
        "proto": sess["proto"],
        "packets": packets_b64,

        # Optional L7 hints if your classifier wants them:
        "seen_http": sess.get("seen_http", False),
        "seen_ftp": sess.get("seen_ftp", False),
        "seen_dns": sess.get("seen_dns", False),
        "seen_telnet": sess.get("seen_telnet", False),
        "seen_tls": sess.get("seen_tls", False),
        "seen_ssh": sess.get("seen_ssh", False),
        "http_host": sess.get("http_host"),
        "http_path": sess.get("http_path"),
        "http_method": sess.get("http_method"),
        "tls_ja3": sess.get("tls_ja3"),
        "tls_sni": sess.get("tls_sni"),
    }

    try:
        r = requests.post(url, json=body, timeout=0.5)
        print(f"[DEBUG] Classifier HTTP status for {sess['key']}: {r.status_code}")
        if r.status_code == 200:
            resp = r.json()
            sess["decision_action"] = resp.get("action", "allow")
            sess["decision_label"] = resp.get("label", "unknown")
            sess["decision_score"] = float(resp.get("score", 0.0))
            sess["decision_tier"] = resp.get("tier", "unknown")
            sess["decision_reason"] = resp.get("reason", "")
            print(
                f"[DEBUG] Classifier decision for {sess['key']}: {sess['decision_action']} "
                f"label={sess['decision_label']} score={sess['decision_score']} tier={sess['decision_tier']}"
            )
        else:
            sess["decision_action"] = "allow"
            sess["decision_label"] = "default_allow_http_error"
            sess["decision_score"] = 0.5
            sess["decision_tier"] = "fallback"
            sess["decision_reason"] = f"http_status_{r.status_code}"
            print(f"[DEBUG] Non-200 status for {sess['key']}, defaulting to allow")
    except Exception as e:
        sess["decision_action"] = "allow"
        sess["decision_label"] = "default_allow_exception"
        sess["decision_score"] = 0.5
        sess["decision_tier"] = "fallback"
        sess["decision_reason"] = "classifier_timeout_or_error"
        print(f"[DEBUG] Exception contacting classifier for {sess['key']}: {e}, defaulting to allow")

    sess["sent_for_classification"] = True
    upsert_session(sess)


def decide_action(sess):
    """
    Decide allow/block for this flow, using:
    - early allow for first 9 packets
    - classification at packet 10
    - cached decision afterwards
    """
    pkt_count = sess["pkt_count"]

    # If we already have a decision, reuse it
    if sess["decision_action"] is not None:
        print(f"[DEBUG] Using existing decision for {sess['key']}: {sess['decision_action']}")
        return sess["decision_action"]

    # Warm-up: let first 9 packets pass
    if pkt_count < 10:
        print(f"[DEBUG] Flow {sess['key']} pkt_count={pkt_count} < 10, auto-allow")
        return "allow"

    # Packet 10 triggers classification
    if pkt_count == 10:
        print(f"[DEBUG] Flow {sess['key']} reached 10 packets, triggering classification")
        if not sess["sent_for_classification"]:
            send_for_classification(sess)
        return "allow"

    # pkt_count > 10 but not classified yet: force classification
    if not sess["sent_for_classification"]:
        print(f"[DEBUG] Flow {sess['key']} pkt_count={pkt_count} > 10 but not classified yet, forcing classification")
        send_for_classification(sess)

    action = sess["decision_action"] or "allow"
    print(f"[DEBUG] Post-classification action for {sess['key']}: {action}")
    return action


# --------------------------------------------------------------------
# Access control + SOAR
# --------------------------------------------------------------------

def is_flow_blocklisted(sess):
    """
    IP-based blocklist:
      - Check access_control.ip against ip_src or ip_dst.
      - Cache result in sess['is_blocklisted'].
    """
    if DB_CONN is None:
        return False

    if sess.get("is_blocklisted") is not None:
        return sess["is_blocklisted"]

    ip_src = sess["ip_src"]
    ip_dst = sess["ip_dst"]

    try:
        c = DB_CONN.cursor()
        c.execute(
            "SELECT 1 FROM access_control WHERE ip IN (?, ?) AND action = 'block' LIMIT 1",
            (ip_src, ip_dst),
        )
        row = c.fetchone()
        sess["is_blocklisted"] = bool(row)
        if sess["is_blocklisted"]:
            print(
                f"[DEBUG] IP blocklist hit for flow {sess['key']} "
                f"(ip_src={ip_src}, ip_dst={ip_dst})"
            )
        return sess["is_blocklisted"]
    except Exception as e:
        print(f"[DEBUG] access_control IP lookup error for {sess['key']}: {e}")
        sess["is_blocklisted"] = False
        return False


def log_soar_action(sess, source, action, label, reason):
    """
    Log a SOAR action into soar_actions table.
    """
    if DB_CONN is None:
        return
    if sess.get("soar_block_logged") and action == "block" and source == "access_control":
        return

    feats = compute_flow_stats(sess)
    ts = time.time()

    try:
        c = DB_CONN.cursor()
        c.execute(
            """
            INSERT INTO soar_actions (
                ts, flow_key,
                ip_src, ip_dst,
                sport, dport, proto,
                state,
                sbytes, dbytes,
                Spkts, Dpkts,
                action, label, score, tier, reason, source
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                ts,
                sess["key"],
                sess["ip_src"],
                sess["ip_dst"],
                sess["sport"],
                sess["dport"],
                sess["proto"],
                sess["conn_state"],
                feats["sbytes"],
                feats["dbytes"],
                feats["Spkts"],
                feats["Dpkts"],
                action,
                label,
                float(sess.get("decision_score") or 0.0),
                sess.get("decision_tier") or "",
                reason,
                source,
            ),
        )
        DB_CONN.commit()
        print(f"[DEBUG] Logged SOAR action for {sess['key']} source={source} action={action}")
        if source == "access_control" and action == "block":
            sess["soar_block_logged"] = True
    except Exception as e:
        print(f"[DEBUG] SOAR logging error for {sess['key']}: {e}")


# --------------------------------------------------------------------
# Main packet processing
# --------------------------------------------------------------------

def process_packet(if_in, if_out, data, sock_out):
    now = time.time()
    print(f"[DEBUG] Packet received on {if_in}, length={len(data)}")

    l2 = parse_eth_header(data)
    if not l2:
        print("[DEBUG] No L2 header parsed, dropping silently")
        return

    if l2["ethertype"] != 0x0800:
        print(f"[DEBUG] Non-IPv4 ethertype={hex(l2['ethertype'])}, forwarding without inspection")
        sock_out.send(data)
        return

    ip = parse_ipv4_header(data)
    if not ip:
        print("[DEBUG] Failed to parse IPv4 header, forwarding")
        sock_out.send(data)
        return

    if ip["protocol"] != 6:
        print(f"[DEBUG] Non-TCP protocol={ip['protocol']}, forwarding")
        sock_out.send(data)
        return

    l4_offset = 14 + ip["header_len_bytes"]
    tcp = parse_tcp_header(data, l4_offset)
    if not tcp:
        print("[DEBUG] Failed to parse TCP header, forwarding")
        sock_out.send(data)
        return

    payload_offset = l4_offset + tcp["data_offset"] * 4
    if payload_offset > len(data):
        payload_offset = len(data)
    payload = data[payload_offset:]

    key, sess = update_session(ip, tcp, data, payload, now)
    update_flow_window(sess, now)
    upsert_session(sess)

    # Apply IP-based access control before ML
    if is_flow_blocklisted(sess):
        sess["decision_action"] = "block"
        sess["decision_label"] = "access_control"
        sess["decision_score"] = 1.0
        sess["decision_tier"] = "access_control"
        sess["decision_reason"] = "ip_blocklist"
        upsert_session(sess)
        log_soar_action(
            sess,
            source="access_control",
            action="block",
            label="access_control",
            reason="ip_blocklist",
        )
        print(f"[DEBUG] Flow {key} blocked by IP access_control, dropping packet")
        return

    action = decide_action(sess)
    print(f"[DEBUG] Final action for packet in flow {key}: {action}")

    if action == "allow":
        sock_out.send(data)

    label = sess["decision_label"] or "none"
    score = sess["decision_score"] if sess["decision_score"] is not None else 0.0
    tier = sess["decision_tier"] or "none"
    reason = sess["decision_reason"] or "none"
    with open(LOG_FILE, "a") as f:
        f.write(
            f"{time.strftime('%Y-%m-%d %H:%M:%S')} {if_in}->{if_out} "
            f"{key} pkt={sess['pkt_count']} action={action} "
            f"label={label} score={score:.2f} tier={tier} reason={reason} state={sess['conn_state']}\n"
        )


# --------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------

def main():
    init_db()
    if0 = "tap0"
    if1 = "tap1"
    print(f"[+] Opening raw sockets on {if0} and {if1}...")
    try:
        s0 = open_iface(if0)
        s1 = open_iface(if1)
    except OSError as e:
        print(f"[-] Failed to open TAP interfaces: {e}")
        sys.exit(1)

    print("[+] Inline forwarder (tap0<->tap1) with 10-packet warmup + ML classifier running (Ctrl+C to stop)")
    PKT_OUT = getattr(socket, "PACKET_OUTGOING", 4)

    try:
        while True:
            r, _, _ = select.select([s0, s1], [], [])
            if s0 in r:
                data, addr = s0.recvfrom(65535)
                if addr[2] != PKT_OUT:
                    process_packet("tap0", "tap1", data, s1)
                else:
                    print("[DEBUG] Ignoring outgoing packet on tap0")
            if s1 in r:
                data, addr = s1.recvfrom(65535)
                if addr[2] != PKT_OUT:
                    process_packet("tap1", "tap0", data, s0)
                else:
                    print("[DEBUG] Ignoring outgoing packet on tap1")
    except KeyboardInterrupt:
        print("\n[+] Stopped by user.")
    finally:
        s0.close()
        s1.close()
        if DB_CONN is not None:
            DB_CONN.close()
            print("[DEBUG] Closed SQLite connection")
        print("[+] Closed sockets. Bye!")


if __name__ == "__main__":
    main()
