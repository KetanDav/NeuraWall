#!/usr/bin/env python3
"""
Flask server to:
- Read flow features for a given session_id from session.db (SQLite)
- Use a CatBoost .cbm model (same folder) to predict anomaly / attack
- Return JSON: {"session_id": "...", "label": <0/1>, "prob_attack": <float>}

Assumptions:
- SQLite DB file: session.db   (in same folder as this script)
- Table name: flow_features
- First column of flow_features = session_id (unique)
- All other columns = features used by the CatBoost model
- CatBoost model file: model.cbm (in same folder as this script)
"""

import os
import sqlite3
from flask import Flask, jsonify, abort
from catboost import CatBoostClassifier  # use CatBoostRegressor if your model is regressor

app = Flask(__name__)

# Paths relative to this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "sessions.db")
MODEL_PATH = os.path.join(BASE_DIR, "models/model.cbm")

# Globals initialized at startup
FIRST_COL_NAME = None       # name of session_id column
FEATURE_COL_NAMES = []      # list of feature column names (in order)
MODEL = None                # loaded CatBoost model
INITIALIZED = False         # flag for one-time init


# ------------------ DB Helpers ------------------ #

def get_db():
    """Open a connection to session.db with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def detect_columns():
    """
    Detect:
      - FIRST_COL_NAME: name of first column (session_id)
      - FEATURE_COL_NAMES: all other columns in order
    Uses PRAGMA table_info(flow_features).
    """
    global FIRST_COL_NAME, FEATURE_COL_NAMES

    conn = get_db()
    cur = conn.execute("PRAGMA table_info(flow_features);")
    cols = cur.fetchall()
    conn.close()

    if not cols:
        raise RuntimeError("Table 'flow_features' does not exist or has no columns")

    # PRAGMA table_info returns rows: (cid, name, type, notnull, dflt_value, pk)
    FIRST_COL_NAME = cols[0]["name"]
    FEATURE_COL_NAMES = [c["name"] for c in cols[1:]]

    print(f"[INFO] Session ID column detected as: {FIRST_COL_NAME}")
    print(f"[INFO] Feature columns detected as: {FEATURE_COL_NAMES}")


def load_model():
    """Load CatBoost model from MODEL_PATH into global MODEL."""
    global MODEL
    if not os.path.exists(MODEL_PATH):
        raise RuntimeError(f"Model file not found: {MODEL_PATH}")

    MODEL = CatBoostClassifier()  # change to CatBoostRegressor() if needed
    MODEL.load_model(MODEL_PATH)
    print(f"[INFO] Loaded CatBoost model from {MODEL_PATH}")


# ------------------ Flask Init Hook (Flask 3 compatible) ------------------ #

@app.before_request
def init():
    """
    Initialize DB metadata and model once on the first incoming request.
    Replaces deprecated before_first_request (removed in Flask 3).
    """
    global INITIALIZED

    if INITIALIZED:
        return

    if not os.path.exists(DB_PATH):
        raise RuntimeError(f"Database file not found: {DB_PATH}")

    detect_columns()
    load_model()
    INITIALIZED = True
    print("[INFO] Initialization complete")


# ------------------ API Route ------------------ #

@app.route("/predict/<session_id>", methods=["GET"])
def predict_for_session(session_id):
    """
    Steps:
    1. Fetch row from flow_features where first_column == session_id
    2. Build feature vector from remaining columns (FEATURE_COL_NAMES)
    3. Use CatBoost model to predict:
       - label (0/1)
       - prob_attack (probability of class 1)
    4. Return JSON:
       {
         "session_id": "...",
         "label": <int>,
         "prob_attack": <float or null>
       }
    """
    # 1. Fetch the row
    conn = get_db()
    query = f"SELECT * FROM flow_features WHERE {FIRST_COL_NAME} = ? LIMIT 1"
    cur = conn.execute(query, (session_id,))
    row = cur.fetchone()
    conn.close()

    if row is None:
        abort(404, description="Session ID not found")

    # 2. Build feature vector in correct order
    try:
        features = [row[col] for col in FEATURE_COL_NAMES]
    except KeyError as e:
        abort(500, description=f"Missing expected feature column in DB: {e}")

    # 3a. Predict label
    try:
        # MODEL.predict returns array-like: [label]
        label = int(MODEL.predict([features])[0])
    except Exception as e:
        abort(500, description=f"Prediction error: {e}")

    # 3b. Predict probability of attack (class 1)
    prob_attack = None
    try:
        proba = MODEL.predict_proba([features])[0]  # e.g. [p0, p1]
        if len(proba) > 1:
            prob_attack = float(proba[1])           # probability of class 1 (attack)
        else:
            prob_attack = float(proba[0])           # degenerate/binary case
    except Exception:
        # If predict_proba not available (e.g., regressor), leave as None
        prob_attack = None

    # 4. Return in requested JSON format
    return jsonify(
        {
            "session_id": session_id,
            "label": label,
            "prob_attack": prob_attack,
        }
    )


# ------------------ Main ------------------ #

if __name__ == "__main__":
    # Expose on all interfaces, port 5001
    app.run(host="0.0.0.0", port=6001, debug=True)
