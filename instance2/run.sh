#!/usr/bin/env bash

set -e

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$BASE_DIR/venv"

echo "[+] Starting NGFW stack"
echo "[+] Base dir: $BASE_DIR"
echo "[+] Using venv: $VENV_DIR"
echo

# -------------------------
# ACTIVATE VENV
# -------------------------
if [ ! -d "$VENV_DIR" ]; then
    echo "[-] venv not found at $VENV_DIR"
    exit 1
fi

source "$VENV_DIR/bin/activate"

echo "[✓] Virtual environment activated"
echo

# -------------------------
# OPTIONAL COMMON SETUP
# -------------------------
if [ -f "$BASE_DIR/taps.sh" ]; then
    echo "[*] Running taps.sh (sudo)"
    sudo bash "$BASE_DIR/taps.sh"
fi

# -------------------------
# START SERVICES (ORDERED)
# -------------------------

echo "[+] Starting anomaly.py"
python3 anomaly.py &

sleep 2

echo "[+] Starting fastclass.py"
python3 fastclass.py &

sleep 2

echo "[+] Starting decision.py"
python3 decision.py &

sleep 2

echo "[+] Starting ids.py"
python3 ids.py &

sleep 2

echo "[+] Starting SOAR (sudo)"
sudo "$VENV_DIR/bin/python3" soar.py &

sleep 2

echo "[+] Starting forwarder (sudo)"
sudo "$VENV_DIR/bin/python3" forwarder.py &

sleep 2

echo "[+] Starting dashboard (Streamlit)"
streamlit run dashboard.py &

echo
echo "[✓] All services started successfully"
echo "[!] Use Ctrl+C to stop (or pkill python if needed)"
