#!/usr/bin/env python3
"""
SOAR API

Endpoints:
- POST /block
    JSON: { "ip": "192.168.100.23" }

    Behavior:
    - Validates IP
    - Creates a record in SQLite (sessions.db, table soar_actions) with action="block"
    - Applies iptables rules to block traffic to/from that IP (INPUT, OUTPUT, FORWARD)
    - Sends an email from altcp.002@gmail.com to chinmay.p0704@gmail.com
    - Updates ticket status: success / partial / failed

- POST /quarantine
    JSON: { "ip": "192.168.100.23" }

    Behavior:
    - Validates IP
    - Creates a record with action="quarantine"
    - Applies STRICT iptables rules: LOG + DROP all traffic to/from that IP
    - Sends email
    - Updates ticket status

- POST /unquarantine
    JSON: { "ip": "192.168.100.23" }

    Behavior:
    - Validates IP
    - Creates a record with action="unquarantine"
    - Removes quarantine iptables rules for that IP
    - Sends email
    - Updates ticket status

NOTE:
- Uses sessions.db in the same folder.
- Table schema (unchanged):
    CREATE TABLE IF NOT EXISTS soar_actions (
        ticket_id TEXT PRIMARY KEY,
        action TEXT,
        ip TEXT,
        status TEXT,
        created_at TEXT
    );
- Run this as root (iptables).
"""

import os
import ipaddress
import sqlite3
import subprocess
from datetime import datetime
from typing import Tuple

from flask import Flask, request, jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

# -------------------
# CONFIG
# -------------------

# sessions.db in same folder
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sessions.db")

# Chains to affect
IPTABLES_CHAINS = ["INPUT", "OUTPUT", "FORWARD"]

# Email config
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_FROM = "altcp.002@gmail.com"
EMAIL_TO = "chinmay.p0704@gmail.com"

# Gmail app password (no spaces)
GMAIL_APP_PASSWORD = "kdfkzffvhuqnacrd"


# -------------------
# DB helpers
# -------------------

def init_db():
    """
    Create soar_actions table if not exists in sessions.db.

    IMPORTANT: Schema is kept exactly as you specified:
        ticket_id TEXT PRIMARY KEY,
        action TEXT,
        ip TEXT,
        status TEXT,
        created_at TEXT
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS soar_actions (
                ticket_id TEXT PRIMARY KEY,
                action TEXT,
                ip TEXT,
                status TEXT,
                created_at TEXT
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def generate_ticket_id() -> str:
    now = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return f"T-{now}"


def create_ticket(action: str, ip: str, status: str) -> str:
    ticket_id = generate_ticket_id()
    created_at = datetime.utcnow().isoformat()

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO soar_actions (ticket_id, action, ip, status, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (ticket_id, action, ip, status, created_at),
        )
        conn.commit()
    finally:
        conn.close()

    return ticket_id


def update_ticket_status(ticket_id: str, status: str):
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE soar_actions SET status = ? WHERE ticket_id = ?",
            (status, ticket_id),
        )
        conn.commit()
    finally:
        conn.close()


# -------------------
# Email helper
# -------------------

def send_email(subject: str, body: str) -> Tuple[bool, str]:
    """Send email via Gmail SMTP."""
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_FROM, GMAIL_APP_PASSWORD)
        server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        server.quit()

        return True, "Email sent successfully"
    except Exception as e:
        return False, f"Email error: {e}"


# -------------------
# iptables helpers
# -------------------

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def apply_iptables_block(ip: str) -> Tuple[bool, str]:
    """
    Add iptables rules to drop traffic to/from IP on INPUT, OUTPUT, FORWARD.
    Simpler "block" action (no LOG).
    """
    commands = []
    for chain in IPTABLES_CHAINS:
        commands.append(["iptables", "-A", chain, "-s", ip, "-j", "DROP"])
        commands.append(["iptables", "-A", chain, "-d", ip, "-j", "DROP"])

    try:
        for cmd in commands:
            subprocess.run(cmd, check=True)
        return True, "iptables rules applied for blocking"
    except subprocess.CalledProcessError as e:
        return False, f"iptables error: {e}"
    except Exception as e:
        return False, f"unexpected error: {e}"


def apply_quarantine_rules(ip: str) -> Tuple[bool, str]:
    """
    Apply STRICT quarantine rules for IP:
    For each chain (INPUT, OUTPUT, FORWARD):
      - LOG limited attempts from IP, then DROP
      - LOG limited attempts to IP, then DROP
    """
    commands = []

    for chain in IPTABLES_CHAINS:
        # Log and drop traffic FROM ip
        commands.append([
            "iptables", "-A", chain,
            "-s", ip,
            "-m", "limit", "--limit", "5/min",
            "-j", "LOG",
            "--log-prefix", f"QUAR_{chain}_S: ",
            "--log-level", "4"
        ])
        commands.append([
            "iptables", "-A", chain,
            "-s", ip,
            "-j", "DROP"
        ])

        # Log and drop traffic TO ip
        commands.append([
            "iptables", "-A", chain,
            "-d", ip,
            "-m", "limit", "--limit", "5/min",
            "-j", "LOG",
            "--log-prefix", f"QUAR_{chain}_D: ",
            "--log-level", "4"
        ])
        commands.append([
            "iptables", "-A", chain,
            "-d", ip,
            "-j", "DROP"
        ])

    try:
        for cmd in commands:
            subprocess.run(cmd, check=True)
        return True, "iptables quarantine rules (LOG+DROP) applied"
    except subprocess.CalledProcessError as e:
        return False, f"iptables error: {e}"
    except Exception as e:
        return False, f"unexpected error: {e}"


def remove_quarantine_rules(ip: str) -> Tuple[bool, str]:
    """
    Remove quarantine rules for IP.

    We attempt to delete the same rules we added in apply_quarantine_rules().
    If some rules are missing, we ignore those errors and still try the rest.

    Returns True if at least one rule deletion succeeded, False otherwise.
    """
    delete_commands = []

    for chain in IPTABLES_CHAINS:
        # Delete FROM-ip LOG and DROP rules
        delete_commands.append([
            "iptables", "-D", chain,
            "-s", ip,
            "-m", "limit", "--limit", "5/min",
            "-j", "LOG",
            "--log-prefix", f"QUAR_{chain}_S: ",
            "--log-level", "4"
        ])
        delete_commands.append([
            "iptables", "-D", chain,
            "-s", ip,
            "-j", "DROP"
        ])
        # Delete TO-ip LOG and DROP rules
        delete_commands.append([
            "iptables", "-D", chain,
            "-d", ip,
            "-m", "limit", "--limit", "5/min",
            "-j", "LOG",
            "--log-prefix", f"QUAR_{chain}_D: ",
            "--log-level", "4"
        ])
        delete_commands.append([
            "iptables", "-D", chain,
            "-d", ip,
            "-j", "DROP"
        ])

    any_success = False
    errors = []

    for cmd in delete_commands:
        try:
            subprocess.run(cmd, check=True)
            any_success = True
        except subprocess.CalledProcessError as e:
            errors.append(str(e))
        except Exception as e:
            errors.append(str(e))

    if any_success:
        msg = "Quarantine iptables rules removed"
        if errors:
            msg += f" (with some errors: {errors})"
        return True, msg
    else:
        return False, f"No quarantine rules removed (errors: {errors})"


# -------------------
# API endpoint: /block
# -------------------

@app.route("/block", methods=["POST"])
def block_ip():
    """
    POST /block
    JSON: { "ip": "192.168.100.23" }

    Status values stored in DB:
    - "pending"  (before actions)
    - "failed"   (iptables failed)
    - "success"  (iptables ok + email ok)
    - "partial"  (iptables ok, email failed)
    """
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")

    if not ip or not is_valid_ip(ip):
        return jsonify({
            "status": "error",
            "error": "invalid_ip",
            "message": f"Invalid or missing IP: {ip}"
        }), 400

    # 1. Create ticket as pending
    ticket_id = create_ticket(action="block", ip=ip, status="pending")

    # 2. Apply iptables block
    ipt_ok, ipt_msg = apply_iptables_block(ip)

    if not ipt_ok:
        update_ticket_status(ticket_id, status="failed")
        return jsonify({
            "status": "error",
            "ticket_id": ticket_id,
            "ip": ip,
            "message": f"Failed to block IP: {ipt_msg}"
        }), 500

    # 3. Send email
    subject = f"[SOAR] BLOCK applied for {ip}"
    body = (
        f"SOAR Alert - BLOCK\n\n"
        f"IP: {ip}\n"
        f"Ticket: {ticket_id}\n"
        f"Action: block\n"
        f"iptables: {ipt_msg}\n"
        f"Timestamp: {datetime.utcnow().isoformat()} UTC\n"
    )
    email_ok, email_msg = send_email(subject, body)

    # 4. Update ticket status
    final_status = "success" if email_ok else "partial"
    update_ticket_status(ticket_id, final_status)

    # 5. Response
    return jsonify({
        "status": final_status,
        "ticket_id": ticket_id,
        "ip": ip,
        "iptables_result": ipt_msg,
        "email_sent": email_ok,
        "email_info": email_msg
    }), 200


# -------------------
# API endpoint: /quarantine
# -------------------

@app.route("/quarantine", methods=["POST"])
def quarantine_ip():
    """
    POST /quarantine
    JSON: { "ip": "192.168.100.23" }

    Status values in DB:
    - "pending"
    - "failed"
    - "success"
    - "partial"
    """
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")

    if not ip or not is_valid_ip(ip):
        return jsonify({
            "status": "error",
            "error": "invalid_ip",
            "message": f"Invalid or missing IP: {ip}"
        }), 400

    # 1. Create ticket as pending
    ticket_id = create_ticket(action="quarantine", ip=ip, status="pending")

    # 2. Apply stricter quarantine rules (LOG+DROP)
    q_ok, q_msg = apply_quarantine_rules(ip)

    if not q_ok:
        update_ticket_status(ticket_id, status="failed")
        return jsonify({
            "status": "error",
            "ticket_id": ticket_id,
            "ip": ip,
            "message": f"Failed to quarantine IP: {q_msg}"
        }), 500

    # 3. Send email
    subject = f"[SOAR] QUARANTINE applied for {ip}"
    body = (
        f"SOAR Alert - QUARANTINE\n\n"
        f"IP: {ip}\n"
        f"Ticket: {ticket_id}\n"
        f"Action: quarantine\n"
        f"Details: {q_msg}\n"
        f"Timestamp: {datetime.utcnow().isoformat()} UTC\n"
    )
    email_ok, email_msg = send_email(subject, body)

    # 4. Update ticket status
    final_status = "success" if email_ok else "partial"
    update_ticket_status(ticket_id, final_status)

    # 5. Response
    return jsonify({
        "status": final_status,
        "ticket_id": ticket_id,
        "ip": ip,
        "quarantine_result": q_msg,
        "email_sent": email_ok,
        "email_info": email_msg
    }), 200


# -------------------
# API endpoint: /unquarantine
# -------------------

@app.route("/unquarantine", methods=["POST"])
def unquarantine_ip():
    """
    POST /unquarantine
    JSON: { "ip": "192.168.100.23" }

    Removes quarantine iptables rules for that IP.
    Creates action 'unquarantine' in soar_actions.
    """
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")

    if not ip or not is_valid_ip(ip):
        return jsonify({
            "status": "error",
            "error": "invalid_ip",
            "message": f"Invalid or missing IP: {ip}"
        }), 400

    # 1. Create ticket as pending
    ticket_id = create_ticket(action="unquarantine", ip=ip, status="pending")

    # 2. Remove quarantine rules
    ok, msg = remove_quarantine_rules(ip)

    if not ok:
        update_ticket_status(ticket_id, status="failed")
        return jsonify({
            "status": "error",
            "ticket_id": ticket_id,
            "ip": ip,
            "message": f"Failed to remove quarantine rules: {msg}"
        }), 500

    # 3. Send email
    subject = f"[SOAR] UNQUARANTINE applied for {ip}"
    body = (
        f"SOAR Action - UNQUARANTINE\n\n"
        f"IP: {ip}\n"
        f"Ticket: {ticket_id}\n"
        f"Action: unquarantine\n"
        f"Details: {msg}\n"
        f"Timestamp: {datetime.utcnow().isoformat()} UTC\n"
    )
    email_ok, email_msg = send_email(subject, body)

    # 4. Update ticket status
    final_status = "success" if email_ok else "partial"
    update_ticket_status(ticket_id, final_status)

    # 5. Response
    return jsonify({
        "status": final_status,
        "ticket_id": ticket_id,
        "ip": ip,
        "unquarantine_result": msg,
        "email_sent": email_ok,
        "email_info": email_msg
    }), 200


# -------------------
# Main
# -------------------

if __name__ == "__main__":
    init_db()
    # Needs root for iptables
    # Change port here if you want, but 5003 avoids clashing with your other services.
    app.run(host="0.0.0.0", port=6003, debug=True)
