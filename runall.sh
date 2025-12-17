#!/usr/bin/env bash

set -e

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$BASE_DIR/venv"

echo "[+] Starting NGFW (instance1 + instance2)"
echo "[+] Base dir: $BASE_DIR"
echo

# -------------------------
# ACTIVATE VENV
# -------------------------
if [ ! -d "$VENV_DIR" ]; then
    echo "[-] venv not found"
    exit 1
fi

source "$VENV_DIR/bin/activate"
echo "[✓] Virtual environment activated"

# -------------------------
# COMMON SETUP (ONCE)
# -------------------------
if [ -f "$BASE_DIR/taps.sh" ]; then
    echo "[*] Running taps.sh"
    sudo bash "$BASE_DIR/taps.sh"
fi

# -------------------------
# FUNCTION TO START ONE INSTANCE
# -------------------------
start_instance () {
    INST="$1"
    DIR="$BASE_DIR/$INST"

    echo
    echo "[+] Starting $INST"

    if [ ! -d "$DIR" ]; then
        echo "[-] $INST directory not found"
        return
    fi

    cd "$DIR"

    python3 anomaly.py &
    sleep 1

    python3 fastclass.py &
    sleep 1

    python3 decision4.py &
    sleep 1

    sudo python3 soar_api.py &
    sleep 1

    sudo python3 forwarder.py &
    sleep 1

    streamlit run dashboard_app.py &
}

# -------------------------
# START BOTH INSTANCES
# -------------------------
start_instance "instance1" &
start_instance "instance2" &

wait

echo
echo "[✓] Both instances started"
