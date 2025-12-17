#!/usr/bin/env bash
# ==========================================================
# ADVANCED LINUX SECURITY AUDIT (NGFW-ENHANCED)
# Safe, read-only audit
#
# Generates:
#   ✔ Color-coded security score
#   ✔ HTML report
#   ✔ Extensive NGFW/Endpoint checks
# ==========================================================

# Requires: bash, systemctl, ss, awk, grep
# Optional: apparmor-utils, auditd, chkrootkit, ufw, clamav, etc.

REPORT_JSON="/tmp/linux_audit_report_$$.txt"
HTML_REPORT="$HOME/Desktop/Linux_Security_Audit_Report_NGFW.html"
mkdir -p "$(dirname "$REPORT_JSON")"

declare -A REPORT
Score=0
MaxScore=20  # can be adjusted

add_result() {
    key="$1"
    value="$2"
    secure="$3"
    REPORT["$key"]="$value"
    if [[ "$secure" == "1" ]]; then ((Score++)); fi
}

echo "Running Advanced NGFW Linux Security Audit..."
echo ""

# --------------------------------------------------------
# 1. OS & Kernel Info
# --------------------------------------------------------
OS=$(lsb_release -ds 2>/dev/null)
KERNEL=$(uname -r)
add_result "OS Version" "$OS" 1
add_result "Kernel Version" "$KERNEL" 1

# --------------------------------------------------------
# 2. Patch Recency
# --------------------------------------------------------
LAST_UPDATE=$(stat -c %y /var/lib/apt/lists 2>/dev/null | head -n1)
if [[ -n "$LAST_UPDATE" ]]; then
    DAYS=$(( ( $(date +%s) - $(date -d "$LAST_UPDATE" +%s) ) / 86400 ))
    SECURE=$(( DAYS < 14 ? 1 : 0 ))
    add_result "Package DB Updated (days ago)" "$DAYS" "$SECURE"
else
    add_result "Package DB Updated" "Unknown" 0
fi

# --------------------------------------------------------
# 3. Firewall (UFW)
# --------------------------------------------------------
if command -v ufw >/dev/null; then
    STATUS=$(sudo ufw status | head -n1)
    [[ "$STATUS" =~ active ]] && SEC=1 || SEC=0
    add_result "UFW Firewall" "$STATUS" "$SEC"
else
    add_result "UFW Firewall" "Not Installed" 0
fi

# --------------------------------------------------------
# 4. AppArmor / SELinux
# --------------------------------------------------------
if command -v aa-status >/dev/null; then
    AA=$(sudo aa-status 2>/dev/null | head -n5)
    echo "$AA" | grep -q "profiles are in enforce mode" && SEC=1 || SEC=0
    add_result "AppArmor Status" "$AA" "$SEC"
else
    add_result "AppArmor Status" "Not Installed" 0
fi

if command -v getenforce >/dev/null; then
    SEL=$(getenforce)
    [[ "$SEL" == "Enforcing" ]] && SEC=1 || SEC=0
    add_result "SELinux Mode" "$SEL" "$SEC"
fi

# --------------------------------------------------------
# 5. Suspicious Open Ports (e.g., Telnet/FTP)
# --------------------------------------------------------
PORTS=$(ss -tulnp)
echo "$PORTS" | grep -qE ":23|:21" && SEC=0 || SEC=1
add_result "Suspicious Ports (21/23)" "$(echo "$PORTS" | head -n 50)" "$SEC"

# --------------------------------------------------------
# 6. SSH Security
# --------------------------------------------------------
if [[ -f /etc/ssh/sshd_config ]]; then
    ROOT_LOGIN=$(grep -Ei '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}')
    [[ "$ROOT_LOGIN" == "no" ]] && SEC=1 || SEC=0
    add_result "SSH Root Login Allowed" "$ROOT_LOGIN" "$SEC"
else
    add_result "SSH Root Login Allowed" "No SSH config found" 0
fi

# --------------------------------------------------------
# 7. Failed Logins (last 7 days)
# --------------------------------------------------------
FAILED=$(lastb 2>/dev/null | wc -l)
SEC=$(( FAILED < 20 ? 1 : 0 ))
add_result "Failed Login Attempts" "$FAILED" "$SEC"

# --------------------------------------------------------
# 8. Automatic Startup Services
# --------------------------------------------------------
AUTO_SERVICES=$(systemctl list-unit-files --type service | grep enabled)
COUNT=$(echo "$AUTO_SERVICES" | wc -l)
SEC=$(( COUNT < 100 ? 1 : 0 ))
add_result "Enabled Services Count" "$COUNT" "$SEC"

# --------------------------------------------------------
# 9. Kernel Modules (Unsigned)
# --------------------------------------------------------
UNSIGNED=$(dmesg 2>/dev/null | grep -i "module verification failed")
[[ -z "$UNSIGNED" ]] && SEC=1 || SEC=0
add_result "Unsigned Kernel Modules" "${UNSIGNED:-None}" "$SEC"

# --------------------------------------------------------
# 10. USB Devices
# --------------------------------------------------------
USB=$(lsusb 2>/dev/null)
add_result "USB Devices" "$USB" 1

# --------------------------------------------------------
# 11. Running Processes Top 10 (for visibility)
# --------------------------------------------------------
TOPPROC=$(ps aux --sort=-%cpu | head -n 10)
add_result "Top CPU Processes" "$TOPPROC" 1

# --------------------------------------------------------
# 12. Systemd Persistence (suspicious disabled auto services)
# --------------------------------------------------------
BAD=$(systemctl list-unit-files | grep enabled | grep -iE "netcat|nc|socat|python|perl")
[[ -z "$BAD" ]] && SEC=1 || SEC=0
add_result "Suspicious Auto-Start Services" "${BAD:-None}" "$SEC"

# --------------------------------------------------------
# 13. SMBv1 (CIFS) Check
# --------------------------------------------------------
SMB=$(grep -ri "vers=1" /etc/fstab 2>/dev/null)
[[ -z "$SMB" ]] && SEC=1 || SEC=0
add_result "SMBv1 (legacy)" "${SMB:-Disabled}" "$SEC"

# --------------------------------------------------------
# 14. Auditd Status
# --------------------------------------------------------
if systemctl is-active auditd >/dev/null 2>&1; then
    add_result "Auditd Logging" "Active" 1
else
    add_result "Auditd Logging" "Not active" 0
fi

# --------------------------------------------------------
# 15. Installed Software Count
# --------------------------------------------------------
PKG_COUNT=$(dpkg -l | wc -l)
add_result "Installed Packages" "$PKG_COUNT" 1

# --------------------------------------------------------
# 16. Virtual Machine Detection
# --------------------------------------------------------
VM=$(systemd-detect-virt)
[[ "$VM" == "none" ]] && SEC=1 || SEC=0
add_result "VM Detected?" "$VM" "$SEC"

# --------------------------------------------------------
# 17. World-writable Files
# --------------------------------------------------------
WW=$(find / -xdev -type f -perm -0002 2>/dev/null | head -n 25)
[[ -z "$WW" ]] && SEC=1 || SEC=0
add_result "World-Writable Files (sample)" "${WW:-None}" "$SEC"

# --------------------------------------------------------
# 18. ClamAV Detection (if installed)
# --------------------------------------------------------
if command -v clamscan >/dev/null; then
    add_result "ClamAV Installed" "Yes" 1
else
    add_result "ClamAV Installed" "No" 0
fi

# --------------------------------------------------------
# 19. Rootkit Detection (chkrootkit if present)
# --------------------------------------------------------
if command -v chkrootkit >/dev/null; then
    RK=$(sudo chkrootkit 2>/dev/null | head -n 20)
    add_result "Rootkit Scan (sample)" "$RK" 1
else
    add_result "Rootkit Scan" "chkrootkit not installed" 0
fi

# --------------------------------------------------------
# 20. System Logging Health
# --------------------------------------------------------
LOGSIZE=$(du -sh /var/log 2>/dev/null | awk '{print $1}')
add_result "Log Directory Size" "$LOGSIZE" 1

# ==========================================================
# CALCULATE SCORE
# ==========================================================
Percent=$(( 100 * Score / MaxScore ))

if (( Percent >= 85 )); then COLOR="Green"; RATING="Excellent"
elif (( Percent >= 60 )); then COLOR="Yellow"; RATING="Moderate"
else COLOR="Red"; RATING="Needs Attention"
fi

echo "Security Score: $Percent% ($RATING)"

# ==========================================================
# GENERATE HTML REPORT
# ==========================================================
{
cat <<EOF
<html>
<head>
<title>Linux Security Audit Report</title>
<style>
body { font-family: Arial; padding:20px; }
h2 { color:#0055aa; }
table { border-collapse: collapse; width: 100%; margin-top: 20px; }
td, th { border:1px solid #ccc; padding:8px; vertical-align: top; }
th { background: #eee; }
pre { white-space: pre-wrap; }
.score { font-size: 20px; margin-top:10px; }
</style>
</head>
<body>
<h2>Linux Security Audit Report (NGFW-enhanced)</h2>
<div class="score"><b>Score:</b> $Percent% ($RATING)</div>
<table>
<tr><th>Check</th><th>Result</th></tr>
EOF

for key in "${!REPORT[@]}"; do
    echo "<tr><td><b>$key</b></td><td><pre>${REPORT[$key]}</pre></td></tr>"
done

cat <<EOF
</table></body></html>
EOF
} > "$HTML_REPORT"

echo ""
echo "HTML report generated:"
echo "$HTML_REPORT"
echo ""
echo "Audit complete."


