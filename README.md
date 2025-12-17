# 🛡️ NeuraWall — AI-Driven Next-Generation Firewall (NGFW)

> **Inline, Intelligent, Autonomous Network Defense System**  
> Bridging traditional packet filtering with AI-powered threat detection, prioritization, and response.

---

## 📌 Overview

**NeuraWall** is an **AI-driven Next-Generation Firewall (NGFW)** designed to operate **inline** at L2/L3/L4 with intelligent L7 awareness.  
It combines **real-time packet forwarding**, **session-level analytics**, **machine learning–based classification**, and **automated response orchestration** into a single unified system.

The primary objective of NeuraWall is to **reduce alert fatigue**, **prioritize real threats**, and **enable autonomous security decisions** without compromising network performance.

---

## 🎯 Problem Statement

Modern SOC teams face:
- Massive **alert floods**
- Poor **signal-to-noise ratio**
- Static rule-based firewalls
- Fragmented security tools (IDS, IPS, SIEM, SOAR)

**NeuraWall addresses this gap** by:
- Performing **inline inspection**
- Extracting **behavioral features**
- Applying **AI-based risk scoring**
- Executing **policy-driven actions in real time**

---

## 🧠 Core Capabilities

### 🔹 Inline Packet Forwarding
- Operates between TAP interfaces (tap ↔ tap)
- Zero packet loss design
- Transparent to network topology

### 🔹 Flow-Based Session Tracking
- Per-flow state management
- Bi-directional statistics
- Timing, volume, and TCP flag analysis

### 🔹 Multi-Layer Classification
- Plaintext traffic classification
- Encrypted traffic heuristics
- L4-only fallback classification

### 🔹 AI-Driven Decision Engine
- Ensemble risk scoring
- Tier-based threat prioritization
- Explainable decision metadata

### 🔹 Automated Response (SOAR)
- Allow / Block / Quarantine actions
- Event logging for SOC correlation
- Designed for future rule feedback loops

### 🔹 Real-Time Dashboard
- Live session visualization
- Threat analytics
- Unified risk insights

---

## 🏗️ System Architecture

    ┌──────────┐
    │  Network │
    └────┬─────┘
         │
     ┌───▼────┐
     │  tap0  │
     └───┬────┘
         │
┌────────▼────────┐
│ Inline NGFW Core │
│  (Packet Engine)│
└────────┬────────┘
         │
     ┌───▼────┐
     │  tap1  │
     └───┬────┘
         │
    ┌────▼─────┐
    │  Network │
    └──────────┘

---

## 🧩 Project Structure

NeuraWall/
├── core/
│ ├── inline_forwarder.py
│ ├── session_tracker.py
│ ├── packet_parser.py
│ └── feature_extractor.py
│
├── classifiers/
│ ├── fastclass.py
│ ├── plaintext_model.joblib
│ ├── encrypted_model.joblib
│ └── l4_model.joblib
│
├── decision_engine/
│ ├── decision.py
│ ├── scoring.py
│ └── policy.py
│
├── soar/
│ ├── soar_api.py
│ └── response_actions.py
│
├── dashboard/
│ ├── dashboard_app.py
│ └── dashboard_components/
│ ├── sessions_table.py
│ ├── analytics.py
│ └── unified_dashboard.py
│
├── database/
│ ├── schema.sql
│ └── sessions.db
│
├── logs/
│ ├── tap_inline.log
│ └── alerts.log
│
├── scripts/
│ ├── taps.sh
│ └── endpoint.sh
│
├── requirements.txt
├── Dockerfile
└── README.md

---

## 🗄️ Database Schema (Core Highlights)

**Session-based storage model**:

- Flow identifiers
- Packet counters
- Byte statistics
- Timing metrics
- TCP behavior
- AI decision metadata

Designed to support:
- SIEM ingestion
- Historical threat analysis
- Model retraining

---

## ⚙️ Installation

### 🔹 Prerequisites
- Linux (tested on Kali / Ubuntu)
- Python 3.10+
- Root privileges (for raw sockets)
- TAP/TUN support enabled

### 🔹 Clone Repository

```bash
git clone git@github.com:KetanDav/NeuraWall.git
cd NeuraWall
```
### 🔹 Install Dependencies
pip install -r requirements.txt

▶️ Running the System
1️⃣ Create TAP Interfaces
sudo bash scripts/taps.sh

2️⃣ Start Classifier API
python classifiers/fastclass.py

3️⃣ Start Inline Firewall
sudo python core/inline_forwarder.py

4️⃣ Launch Dashboard
streamlit run dashboard/dashboard_app.py

📊 Dashboard Features

Live session table

Risk score visualization

Threat tier distribution

Decision explanations

Traffic behavior analytics

🧪 Detection Scenarios Tested

Port scanning

Abnormal TCP behavior

Encrypted anomaly traffic

Payload entropy spikes

Policy violations

🔐 Security Design Principles

Zero Trust mindset

Default-deny capable

Explainable AI decisions

No cloud dependency

Offline-capable models

🚀 Performance Considerations

Lightweight feature extraction

First-N-packet classification

Asynchronous logging

Minimal packet path latency

🧠 AI & ML Design Philosophy

Behavior > Signature

Risk scoring over binary detection

Tiered confidence system

Model-agnostic architecture

🛣️ Roadmap

 Adaptive rule learning

 Federated model updates

 Active Directory integration

 Threat Intelligence feeds

 High-speed NIC optimization

 Hardware offloading (DPDK)

🧪 Research & Academic Relevance

Suitable for:

Advanced Computing projects

Cybersecurity research

NGFW experimentation

SIEM/SOAR integration studies

👤 Author

Ketan Dav
Cybersecurity | AI Systems | Network Defense
Focused on building autonomous security infrastructure

🔗 GitHub: https://github.com/KetanDav

⚠️ Disclaimer

This project is developed strictly for educational, research, and defensive security purposes.
Do not deploy in production networks without extensive testing and compliance validation.

⭐ Acknowledgements

Open-source security community

Academic research in network ML

Linux networking ecosystem

"Security should not just detect threats — it should understand them."
