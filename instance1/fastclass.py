#!/usr/bin/env python3
from flask import Flask, request, jsonify
import base64
import struct
import sqlite3
import hashlib
import os
import numpy as np

try:
    import joblib
except ImportError:
    joblib = None

DB_FILE = "sessions.db"
PLAINTEXT_MODEL_PATH = "plaintext_model.joblib"
ENCRYPTED_MODEL_PATH = "encrypted_model.joblib"
L4_MODEL_PATH = "l4_model.joblib"

app = Flask(__name__)

DB_CONN = None
PLAINTEXT_MODEL = None
ENCRYPTED_MODEL = None
L4_MODEL = None


def init_db():
    global DB_CONN
    DB_CONN = sqlite3.connect(DB_FILE, check_same_thread=False)
    print(f"[DEBUG] Connected to DB {DB_FILE}")


def load_models():
    global PLAINTEXT_MODEL, ENCRYPTED_MODEL, L4_MODEL
    if joblib is None:
        print("[DEBUG] joblib not installed, classifier will fallback to allow")
        return
    if os.path.exists(PLAINTEXT_MODEL_PATH):
        PLAINTEXT_MODEL = joblib.load(PLAINTEXT_MODEL_PATH)
        print(f"[DEBUG] Loaded PLAINTEXT_MODEL from {PLAINTEXT_MODEL_PATH}")
    else:
        print(f"[DEBUG] No plaintext model at {PLAINTEXT_MODEL_PATH}")
    if os.path.exists(ENCRYPTED_MODEL_PATH):
        ENCRYPTED_MODEL = joblib.load(ENCRYPTED_MODEL_PATH)
        print(f"[DEBUG] Loaded ENCRYPTED_MODEL from {ENCRYPTED_MODEL_PATH}")
    else:
        print(f"[DEBUG] No encrypted model at {ENCRYPTED_MODEL_PATH}")
    if os.path.exists(L4_MODEL_PATH):
        L4_MODEL = joblib.load(L4_MODEL_PATH)
        print(f"[DEBUG] Loaded L4_MODEL from {L4_MODEL_PATH}")
    else:
        print(f"[DEBUG] No L4 model at {L4_MODEL_PATH}")


def mac_to_str(b):
    return ":".join(f"{x:02x}" for x in b)


def parse_eth(pkt):
    if len(pkt) < 14:
        return None, None
    dst = mac_to_str(pkt[0:6])
    src = mac_to_str(pkt[6:12])
    ethertype = int.from_bytes(pkt[12:14], "big")
    return {"src": src, "dst": dst, "ethertype": ethertype}, pkt[14:]


def ip_to_str(ip_bytes):
    return ".".join(str(b) for b in ip_bytes)


def parse_ipv4(payload):
    if len(payload) < 20:
        return None, None
    ver_ihl, tos, total_length, ident, flags_frag, ttl, proto, checksum, src, dst = struct.unpack(
        "!BBHHHBBH4s4s", payload[:20]
    )
    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F
    ip_hlen = ihl * 4
    if version != 4 or len(payload) < ip_hlen:
        return None, None
    src_ip = ip_to_str(src)
    dst_ip = ip_to_str(dst)
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ttl": ttl,
        "proto": proto,
        "header_len": ip_hlen,
        "total_length": total_length,
    }, payload[ip_hlen:]


def parse_tcp(payload):
    if len(payload) < 20:
        return None, None
    src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urg_ptr = struct.unpack(
        "!HHLLHHHH", payload[:20]
    )
    data_offset = (offset_reserved_flags >> 12) & 0xF
    flags = offset_reserved_flags & 0x3F
    if len(payload) < data_offset * 4:
        return None, None
    flag_names = []
    if flags & 0x01:
        flag_names.append("FIN")
    if flags & 0x02:
        flag_names.append("SYN")
    if flags & 0x04:
        flag_names.append("RST")
    if flags & 0x08:
        flag_names.append("PSH")
    if flags & 0x10:
        flag_names.append("ACK")
    if flags & 0x20:
        flag_names.append("URG")
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "data_offset": data_offset,
        "window": window,
        "flags": flag_names,
    }, payload[data_offset * 4:]


def is_printable_ratio(data):
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / float(len(data))


def detect_http(payload):
    try:
        head = payload.split(b"\r\n", 1)[0][:64]
    except Exception:
        return None
    parts = head.split(b" ")
    if len(parts) >= 2:
        m = parts[0].upper()
        if m in [b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH"]:
            path = parts[1]
            return {
                "method": m.decode(errors="ignore"),
                "path_len": len(path),
            }
    return None


def detect_ftp(payload):
    line = payload.split(b"\r\n", 1)[0][:64]
    cmds = [b"USER", b"PASS", b"RETR", b"STOR", b"LIST", b"PWD", b"CWD"]
    for c in cmds:
        if line.upper().startswith(c + b" "):
            return c.decode(errors="ignore")
    return None


def detect_dns_tcp(payload):
    if len(payload) < 4:
        return None
    length = int.from_bytes(payload[0:2], "big")
    if len(payload) < 2 + length or length < 12:
        return None
    dns = payload[2:2+length]
    qdcount = int.from_bytes(dns[4:6], "big")
    if qdcount < 1:
        return None
    idx = 12
    labels = []
    while idx < len(dns):
        l = dns[idx]
        if l == 0:
            idx += 1
            break
        idx += 1
        if idx + l > len(dns):
            return None
        labels.append(dns[idx:idx+l])
        idx += l
    if idx + 4 > len(dns):
        return None
    qtype = int.from_bytes(dns[idx:idx+2], "big")
    qname = b".".join(labels)
    return {"qname_len": len(qname), "qtype": qtype}


def detect_tls_client_hello(payload):
    if len(payload) < 6:
        return None
    if payload[0] != 0x16:
        return None
    if payload[5] != 0x01:
        return None
    pseudo_ja3 = int(hashlib.md5(payload[:64]).hexdigest(), 16) % (10**8)
    sni_len = 0
    try:
        idx = 5
        handshake_type = payload[idx]
        idx += 1
        length = int.from_bytes(payload[idx:idx+3], "big")
        idx += 3
        idx += 2
        idx += 32
        sid_len = payload[idx]
        idx += 1 + sid_len
        cs_len = int.from_bytes(payload[idx:idx+2], "big")
        idx += 2 + cs_len
        comp_len = payload[idx]
        idx += 1 + comp_len
        if idx + 2 > len(payload):
            return {"ja3_hash": pseudo_ja3, "sni_len": 0}
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
            if etype == 0 and e_len >= 5:
                list_len = int.from_bytes(edata[0:2], "big")
                pos = 2
                if pos + 3 <= len(edata):
                    name_type = edata[pos]
                    host_len = int.from_bytes(edata[pos+1:pos+3], "big")
                    pos += 3
                    if pos + host_len <= len(edata):
                        sni_len = host_len
                        break
        return {"ja3_hash": pseudo_ja3, "sni_len": sni_len}
    except Exception:
        return {"ja3_hash": pseudo_ja3, "sni_len": 0}


def detect_ssh(payload):
    if payload.startswith(b"SSH-"):
        return len(payload.split(b"\n", 1)[0])
    return None


def choose_case(agg):
    if agg["seen_tls"]:
        return "encrypted"
    if agg["seen_ssh"]:
        return "encrypted"
    if agg["seen_http"] or agg["seen_ftp"] or agg["seen_dns"] or agg["seen_telnet"]:
        return "plaintext"
    return "l4"


def build_features(agg, case):
    base = [
        agg["sport"],
        agg["dsport"],
        agg["proto"],
        agg["Spkts"],
        agg["Dpkts"],
        agg["sbytes"],
        agg["dbytes"],
        agg["smean_sz"],
        agg["dmean_sz"],
        agg["syn_count"],
        agg["fin_count"],
        agg["rst_count"],
        agg["first_dir"],
    ]
    if case == "plaintext":
        http_m = agg["http_method"]
        http_method_get = 1 if http_m == "GET" else 0
        http_method_post = 1 if http_m == "POST" else 0
        http_method_other = 1 if (http_m not in ["", "GET", "POST"]) else 0
        extras = [
            agg["http_path_len"],
            http_method_get,
            http_method_post,
            http_method_other,
            agg["ftp_cmd_count"],
            agg["dns_qname_len"],
            agg["dns_qtype"],
            agg["telnet_print_ratio"],
        ]
        return np.array(base + extras, dtype=float)
    if case == "encrypted":
        extras = [
            1 if agg["seen_tls"] else 0,
            1 if agg["seen_ssh"] else 0,
            agg["tls_ja3_hash"],
            agg["tls_sni_len"],
            agg["ssh_banner_len"],
        ]
        return np.array(base + extras, dtype=float)
    return np.array(base, dtype=float)


def run_model(features, case):
    model = None
    tier = ""
    if case == "plaintext":
        model = PLAINTEXT_MODEL
        tier = "fast_plaintext"
    elif case == "encrypted":
        model = ENCRYPTED_MODEL
        tier = "fast_encrypted"
    else:
        model = L4_MODEL
        tier = "fast_l4"
    if model is None:
        print(f"[DEBUG] No model for case {case}, default allow")
        return "allow", "no_model", 0.5, tier, "no_model_fallback"
    try:
        X = features.reshape(1, -1)
        y = model.predict(X)[0]
        score = 0.5
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X)
            if proba.shape[1] > 1:
                score = float(max(proba[0]))
        label = str(y)
        if label.lower() in ["malicious", "attack", "1", "bad"]:
            action = "block"
        else:
            action = "allow"
        return action, label, score, tier, "model_decision"
    except Exception as e:
        print(f"[DEBUG] Model error: {e}, default allow")
        return "allow", "model_error", 0.5, tier, "model_exception_fallback"


def update_session_decision(flow_key, action, label, score, tier, reason):
    if DB_CONN is None:
        return
    c = DB_CONN.cursor()
    c.execute(
        """
        UPDATE sessions
        SET decision_action = ?, decision_label = ?, decision_score = ?, decision_tier = ?, decision_reason = ?
        WHERE flow_key = ?
        """,
        (action, label, float(score), tier, reason, flow_key),
    )
    DB_CONN.commit()
    print(f"[DEBUG] Updated sessions decision for {flow_key}: {action} {label} {score} {tier} {reason}")


@app.route("/fastclassify-plain", methods=["POST"])
def fastclassify_plain():
    data = request.get_json(silent=True) or {}
    flow_key = data.get("flow_key") or data.get("session_id")
    packets_b64 = data.get("packets", [])
    print("==========[DEBUG] /fastclassify-plain request==========")
    print(f"[DEBUG] flow_key={flow_key}, packets={len(packets_b64)}")
    if not flow_key or not packets_b64:
        print("[DEBUG] Missing flow_key or packets, default allow")
        action = "allow"
        label = "bad_request"
        score = 0.5
        tier = "fast_l4"
        reason = "missing_flowkey_or_packets"
        if flow_key:
            update_session_decision(flow_key, action, label, score, tier, reason)
        return jsonify(
            {"flow_key": flow_key, "action": action, "label": label, "score": score, "tier": tier, "reason": reason}
        )

    payloads = []
    directions = []
    sport = None
    dsport = None
    proto = 6
    syn_count = 0
    fin_count = 0
    rst_count = 0
    sbytes = 0
    dbytes = 0
    Spkts = 0
    Dpkts = 0
    first_src = None
    first_dir = 0
    sttl = None
    dttl = None

    seen_http = False
    http_method = ""
    http_path_len = 0
    ftp_cmd_count = 0
    dns_qname_len = 0
    dns_qtype = 0
    telnet_print_ratio = 0.0

    seen_tls = False
    tls_ja3_hash = 0.0
    tls_sni_len = 0.0

    seen_ssh = False
    ssh_banner_len = 0.0

    for idx, b64pkt in enumerate(packets_b64):
        try:
            raw = base64.b64decode(b64pkt)
        except Exception as e:
            print(f"[DEBUG] Failed to decode packet {idx}: {e}")
            continue
        eth, rest = parse_eth(raw)
        if not eth or eth["ethertype"] != 0x0800:
            continue
        ip, rest_ip = parse_ipv4(rest)
        if not ip or ip["proto"] != 6:
            continue
        tcp, l7 = parse_tcp(rest_ip)
        if not tcp:
            continue

        src_ip = ip["src_ip"]
        dst_ip = ip["dst_ip"]
        if sport is None:
            sport = tcp["src_port"]
            dsport = tcp["dst_port"]
            first_src = src_ip
            first_dir = 0
        dir_is_fwd = (src_ip == first_src)
        payload_len = ip["total_length"] - ip["header_len"] - tcp["data_offset"] * 4
        if payload_len < 0:
            payload_len = 0
        if dir_is_fwd:
            Spkts += 1
            sbytes += payload_len
            if sttl is None:
                sttl = ip["ttl"]
        else:
            Dpkts += 1
            dbytes += payload_len
            if dttl is None:
                dttl = ip["ttl"]

        flags = tcp["flags"]
        if "SYN" in flags:
            syn_count += 1
        if "FIN" in flags:
            fin_count += 1
        if "RST" in flags:
            rst_count += 1

        payloads.append((l7, dir_is_fwd))

        p_src_port = tcp["src_port"]
        p_dst_port = tcp["dst_port"]

        if payload_len > 0:
            if (p_src_port == 80 or p_dst_port == 80 or p_dst_port in (8080, 8000, 8001)) and not seen_http:
                h = detect_http(l7)
                if h:
                    seen_http = True
                    http_method = h["method"]
                    http_path_len = h["path_len"]
            if (p_src_port == 21 or p_dst_port == 21) and not seen_tls and not seen_ssh:
                ftp_cmd = detect_ftp(l7)
                if ftp_cmd:
                    ftp_cmd_count += 1
            if (p_src_port == 53 or p_dst_port == 53) and not seen_tls and not seen_ssh:
                dns = detect_dns_tcp(l7)
                if dns:
                    seen_http = True
                    dns_qname_len = dns["qname_len"]
                    dns_qtype = dns["qtype"]
            if p_src_port == 23 or p_dst_port == 23:
                r = is_printable_ratio(l7)
                if r > telnet_print_ratio:
                    telnet_print_ratio = r
            if (p_src_port in (443, 8443) or p_dst_port in (443, 8443)) and not seen_tls:
                t = detect_tls_client_hello(l7)
                if t:
                    seen_tls = True
                    tls_ja3_hash = float(t["ja3_hash"])
                    tls_sni_len = float(t["sni_len"])
            if (p_src_port == 22 or p_dst_port == 22) and not seen_ssh:
                ssh_len = detect_ssh(l7)
                if ssh_len is not None:
                    seen_ssh = True
                    ssh_banner_len = float(ssh_len)

    total_pkts = Spkts + Dpkts
    smean_sz = float(sbytes) / Spkts if Spkts > 0 else 0.0
    dmean_sz = float(dbytes) / Dpkts if Dpkts > 0 else 0.0

    if sport is None:
        sport = 0
    if dsport is None:
        dsport = 0
    if sttl is None:
        sttl = 0
    if dttl is None:
        dttl = 0

    agg = {
        "sport": sport,
        "dsport": dsport,
        "proto": proto,
        "Spkts": Spkts,
        "Dpkts": Dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "smean_sz": smean_sz,
        "dmean_sz": dmean_sz,
        "syn_count": syn_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "first_dir": first_dir,
        "seen_http": seen_http,
        "http_method": http_method,
        "http_path_len": http_path_len,
        "ftp_cmd_count": ftp_cmd_count,
        "dns_qname_len": dns_qname_len,
        "dns_qtype": dns_qtype,
        "telnet_print_ratio": telnet_print_ratio,
        "seen_tls": seen_tls,
        "tls_ja3_hash": tls_ja3_hash,
        "tls_sni_len": tls_sni_len,
        "seen_ssh": seen_ssh,
        "ssh_banner_len": ssh_banner_len,
    }

    case = choose_case(agg)
    print(f"[DEBUG] flow_key={flow_key} classified as case={case}")
    feats = build_features(agg, case)
    action, label, score, tier, reason = run_model(feats, case)
    update_session_decision(flow_key, action, label, score, tier, reason)

    return jsonify(
        {
            "flow_key": flow_key,
            "action": action,
            "label": label,
            "score": score,
            "tier": tier,
            "reason": reason,
        }
    )


if __name__ == "__main__":
    print("[DEBUG] Starting classifier server")
    init_db()
    load_models()
    app.run(host="0.0.0.0", port=5000)
