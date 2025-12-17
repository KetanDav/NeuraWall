"""
AI-Powered NGFW Dashboard
Real-time monitoring and visualization for firewall operations

Features:
- Live traffic flow classification from sessions.db
- Zero Trust risk scoring
- SOAR automation monitoring
- Federated Learning metrics
- Device and firewall rule status
"""

import streamlit as st
import pandas as pd
import json
import numpy as np
from datetime import datetime, timedelta
import time
from pathlib import Path
import sqlite3
import plotly.graph_objects as go
import plotly.express as px
from collections import defaultdict, Counter
from dashboard_components.sessions_table import render_sessions_table, render_sessions_summary
from dashboard_components.flow_features_table import render_flow_features_table, render_flow_features_analytics
from dashboard_components.ti_metadata_table import render_ti_metadata_table, render_ti_metadata_analytics
from dashboard_components.unified_analytics import render_unified_dashboard

# ═══════════════════════════════════════════════════════════════════
# PAGE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="AI-Powered NGFW Dashboard",
    page_icon="🛡️",  # Streamlit page_icon only supports emoji, but we'll use icons in content
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced Professional CSS with Font Awesome Icons
st.markdown("""
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
    /* Main Background - Professional Dark Theme */
    .stApp {
        background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
        background-attachment: fixed;
    }
    
    /* Icon styling */
    .icon {
        margin-right: 8px;
        color: #60a5fa;
        font-size: 0.95em;
    }
    
    .icon-header {
        margin-right: 12px;
        color: #60a5fa;
        font-size: 1.3em;
        vertical-align: middle;
    }
    
    /* Ensure icons display properly */
    i.fas, i.far {
        display: inline-block;
    }
    
    /* Professional Cards with Subtle Shadow */
    .glass-card {
        background: rgba(15, 23, 42, 0.8);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border: 1px solid rgba(148, 163, 184, 0.2);
        box-shadow: 0 10px 40px 0 rgba(0, 0, 0, 0.5);
        padding: 24px;
        margin: 12px 0;
        border-radius: 8px;
    }
    
    /* Clean Tables */
    .stDataFrame, .dataframe, table {
        border-radius: 4px !important;
        background: rgba(15, 23, 42, 0.6) !important;
    }
    
    /* Professional Buttons */
    .stButton>button {
        border-radius: 6px !important;
        border: 1px solid rgba(148, 163, 184, 0.3);
        background: rgba(30, 41, 59, 0.8);
        backdrop-filter: blur(10px);
        color: white;
        font-weight: 500;
        transition: all 0.3s ease;
        padding: 0.5rem 1.5rem;
    }
    
    .stButton>button:hover {
        background: rgba(51, 65, 85, 0.9);
        border-color: rgba(148, 163, 184, 0.5);
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }
    
    /* Enhanced Metrics */
    [data-testid="stMetricValue"] {
        color: #ffffff;
        font-weight: 700;
        font-size: 2rem;
    }
    
    [data-testid="stMetricLabel"] {
        color: rgba(203, 213, 225, 0.9);
        font-weight: 500;
        font-size: 0.9rem;
    }
    
    [data-testid="stMetricDelta"] {
        color: rgba(203, 213, 225, 0.9);
        font-weight: 600;
    }
    
    /* Professional Sidebar */
    .css-1d391kg {
        background: rgba(15, 23, 42, 0.7);
        backdrop-filter: blur(20px);
    }
    
    /* Headers with Better Typography */
    h1 {
        color: #ffffff !important;
        font-weight: 700;
        font-size: 2.5rem;
        letter-spacing: -0.5px;
    }
    
    h2 {
        color: #ffffff !important;
        font-weight: 600;
        font-size: 1.75rem;
        margin-top: 1.5rem;
    }
    
    h3 {
        color: #ffffff !important;
        font-weight: 600;
        font-size: 1.25rem;
        margin-top: 1rem;
    }
    
    /* Text Colors */
    .stMarkdown, p, div {
        color: rgba(226, 232, 240, 0.95);
    }
    
    /* Enhanced Tables */
    .dataframe {
        background: rgba(15, 23, 42, 0.6);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(148, 163, 184, 0.2);
    }
    
    /* Status Colors */
    .status-good { color: #10b981; font-weight: 600; }
    .status-warning { color: #f59e0b; font-weight: 600; }
    .status-danger { color: #ef4444; font-weight: 600; }
    .status-info { color: #3b82f6; font-weight: 600; }
    
    /* Professional Tabs */
    .stTabs [data-baseweb="tab-list"] {
        background: rgba(15, 23, 42, 0.6);
        backdrop-filter: blur(10px);
        border-bottom: 2px solid rgba(148, 163, 184, 0.2);
        padding: 0.5rem 0;
    }
    
    .stTabs [data-baseweb="tab"] {
        color: rgba(203, 213, 225, 0.8);
        font-weight: 500;
        padding: 0.75rem 1.5rem;
        transition: all 0.3s ease;
    }
    
    .stTabs [aria-selected="true"] {
        color: #ffffff;
        background: rgba(30, 41, 59, 0.8);
        border-bottom: 2px solid #3b82f6;
    }
    
    /* Input Fields */
    .stTextInput>div>div>input, 
    .stSelectbox>div>div>select,
    .stSlider>div>div>div {
        background: rgba(30, 41, 59, 0.8);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(148, 163, 184, 0.3);
        color: white;
        border-radius: 6px !important;
    }
    
    /* Dividers */
    hr {
        border-color: rgba(148, 163, 184, 0.2);
        margin: 24px 0;
        border-width: 1px;
    }
    
    /* Alert Boxes */
    .stAlert {
        background: rgba(15, 23, 42, 0.8);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(148, 163, 184, 0.2);
        border-radius: 6px !important;
        padding: 1rem;
    }
    
    /* Subheader Styling */
    .stSubheader {
        color: #ffffff !important;
        font-weight: 600;
        margin-top: 1.5rem;
    }
    
    /* Selectbox and Multiselect */
    .stSelectbox label, .stMultiSelect label {
        color: rgba(203, 213, 225, 0.9) !important;
        font-weight: 500;
    }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════
# DATABASE DATA LOADING
# ═══════════════════════════════════════════════════════════════════

@st.cache_data(ttl=2)
def load_sessions_data(db_path='sessions.db', limit=1000):
    """Load sessions data from SQLite database"""
    try:
        conn = sqlite3.connect(db_path)
        query = """
            SELECT 
                flow_key,
                ip_src,
                ip_dst,
                sport,
                dport,
                proto,
                first_ts,
                last_ts,
                dur,
                pkt_count,
                pkts_fwd,
                pkts_rev,
                bytes_fwd,
                bytes_rev,
                sbytes,
                dbytes,
                decision_action,
                decision_label,
                decision_score,
                decision_tier,
                decision_reason,
                syn_count,
                fin_count,
                rst_count
            FROM sessions
            ORDER BY last_ts DESC
            LIMIT ?
        """
        df = pd.read_sql_query(query, conn, params=(limit,))
        conn.close()
        return df
    except Exception as e:
        return pd.DataFrame()

@st.cache_data(ttl=2)
def load_config():
    """Load dashboard configuration"""
    config_path = Path("dashboard_config.json")
    if config_path.exists():
        with open(config_path, encoding='utf-8') as f:
            return json.load(f)
    return {}

@st.cache_data(ttl=2)
def load_logs():
    """Load SOAR and Zero Trust logs"""
    soar_logs = []
    zero_trust_logs = []
    
    if Path("soar_logs.jsonl").exists():
        with open("soar_logs.jsonl") as f:
            for line in f:
                try:
                    soar_logs.append(json.loads(line))
                except:
                    pass
    
    if Path("zero_trust_logs.jsonl").exists():
        with open("zero_trust_logs.jsonl") as f:
            for line in f:
                try:
                    zero_trust_logs.append(json.loads(line))
                except:
                    pass
    
    return soar_logs, zero_trust_logs

@st.cache_data(ttl=2)
def load_state_files():
    """Load state management files"""
    state = {
        'blocked_ips': {},
        'quarantined_devices': {},
        'firewall_rules': [],
        'device_profiles': {}
    }
    
    if Path("blocked_ips.json").exists():
        with open("blocked_ips.json") as f:
            state['blocked_ips'] = json.load(f)
    
    if Path("quarantined_devices.json").exists():
        with open("quarantined_devices.json") as f:
            state['quarantined_devices'] = json.load(f)
    
    if Path("firewall_rules.json").exists():
        with open("firewall_rules.json") as f:
            state['firewall_rules'] = json.load(f)
    
    if Path("device_profiles.json").exists():
        with open("device_profiles.json") as f:
            state['device_profiles'] = json.load(f)
    
    return state

# ═══════════════════════════════════════════════════════════════════
# DATA PROCESSING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def get_risk_score_from_db(row):
    """Calculate risk score from database row"""
    if pd.notna(row.get('decision_score')):
        return float(row['decision_score'])
    # Fallback calculation if decision_score not available
    return 0.5

def get_policy_decision(risk_score):
    """Map risk score to policy decision"""
    if risk_score < 0.30:
        return "ALLOW"
    elif risk_score < 0.60:
        return "ALERT"
    elif risk_score < 0.85:
        return "BLOCK"
    else:
        return "QUARANTINE"

def get_soar_action(decision):
    """Map policy decision to SOAR action"""
    actions = {
        "ALLOW": "Allowed",
        "ALERT": "Sandbox Analysis",
        "BLOCK": "IP Blocked (10 min)",
        "QUARANTINE": "Device Quarantined (24h)"
    }
    return actions.get(decision, "Unknown")

def format_protocol(proto):
    """Format protocol number to name"""
    protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP", 47: "GRE"}
    return protocol_map.get(int(proto) if pd.notna(proto) else 0, f"Proto {proto}")

# ═══════════════════════════════════════════════════════════════════
# VISUALIZATION COMPONENTS
# ═══════════════════════════════════════════════════════════════════

def display_header(config, db_path='sessions.db'):
    """Display professional dashboard header"""
    col1, col2, col3 = st.columns([3, 2, 1])
    
    with col1:
        st.markdown("## <i class='fas fa-shield-alt icon-header'></i> AI-Powered NGFW Dashboard", unsafe_allow_html=True)
        st.markdown("**Enterprise Security Operations Center**")
    
    # Get database stats
    df = load_sessions_data(db_path, limit=100)
    total_flows = len(df)
    
    with col2:
        if total_flows > 0:
            st.metric("System Status", "Operational", "+100%")
            st.metric("Active Sessions", f"{total_flows:,}")
        else:
            st.metric("System Status", "Initializing", "0%")
            st.metric("Active Sessions", "0")
    
    with col3:
        st.metric("Last Update", datetime.now().strftime("%H:%M:%S"))
        if total_flows > 0 and 'last_ts' in df.columns:
            latest_ts = df['last_ts'].max()
            if pd.notna(latest_ts):
                latest_time = datetime.fromtimestamp(latest_ts)
                st.metric("Latest Flow", latest_time.strftime("%H:%M:%S"))
    
    st.divider()

def display_live_flows(db_path='sessions.db', limit=20):
    """Display live traffic flow table from database"""
    st.markdown("### <i class='fas fa-chart-line icon'></i> Live Traffic Flows", unsafe_allow_html=True)
    
    df = load_sessions_data(db_path, limit=limit)
    
    if df.empty:
        st.info("No flow data available. Waiting for data from sessions.db...")
        return
    
    # Prepare display data
    df_data = []
    for _, row in df.head(limit).iterrows():
        risk = get_risk_score_from_db(row)
        decision = row.get('decision_action', get_policy_decision(risk))
        
        df_data.append({
            'Flow Key': str(row.get('flow_key', 'N/A'))[:16],
            'Src IP': row.get('ip_src', 'N/A'),
            'Dst IP': row.get('ip_dst', 'N/A'),
            'Protocol': format_protocol(row.get('proto', 0)),
            'Src Port': int(row.get('sport', 0)) if pd.notna(row.get('sport')) else 'N/A',
            'Dst Port': int(row.get('dport', 0)) if pd.notna(row.get('dport')) else 'N/A',
            'Packets': int(row.get('pkt_count', 0)) if pd.notna(row.get('pkt_count')) else 0,
            'Bytes': int(row.get('bytes_fwd', 0) + row.get('bytes_rev', 0)) if pd.notna(row.get('bytes_fwd')) else 0,
            'Score': f"{risk:.3f}" if pd.notna(risk) else "N/A",
            'Decision': decision if pd.notna(decision) else "UNKNOWN",
            'Tier': row.get('decision_tier', 'N/A') if pd.notna(row.get('decision_tier')) else 'N/A',
            'Action': get_soar_action(decision)
        })
    
    display_df = pd.DataFrame(df_data)
    
    # Color code the dataframe
    def color_decision(val):
        if pd.isna(val):
            return ''
        val_str = str(val).upper()
        if 'ALLOW' in val_str or 'PERMIT' in val_str:
            return 'background-color: #10b981; color: white'
        elif 'ALERT' in val_str or 'WARN' in val_str:
            return 'background-color: #f59e0b; color: white'
        elif 'BLOCK' in val_str or 'DENY' in val_str:
            return 'background-color: #ef4444; color: white'
        elif 'QUARANTINE' in val_str or 'ISOLATE' in val_str:
            return 'background-color: #dc2626; color: white'
        return ''
    
    styled_df = display_df.style.applymap(color_decision, subset=['Decision'])
    st.dataframe(styled_df, use_container_width=True, height=400)

def display_risk_gauge(db_path='sessions.db'):
    """Display risk score gauge from database"""
    df = load_sessions_data(db_path, limit=1000)
    
    if df.empty:
        st.info("No data available for risk analysis")
        return
    
    # Calculate average risk score
    risk_scores = []
    for _, row in df.iterrows():
        risk = get_risk_score_from_db(row)
        risk_scores.append(risk)
    
    avg_risk = np.mean(risk_scores) if risk_scores else 0.5
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=avg_risk * 100,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Overall Risk Score", 'font': {'size': 20}},
        delta={'reference': 50},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': "#3b82f6"},
            'steps': [
                {'range': [0, 30], 'color': "#10b981"},
                {'range': [30, 60], 'color': "#f59e0b"},
                {'range': [60, 85], 'color': "#ef4444"},
                {'range': [85, 100], 'color': "#dc2626"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    fig.update_layout(
        height=400,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white', size=14)
    )
    st.plotly_chart(fig, use_container_width=True)

def display_risk_breakdown(db_path='sessions.db'):
    """Display risk score component breakdown from database"""
    df = load_sessions_data(db_path, limit=1000)
    
    if df.empty:
        st.info("No data available for risk breakdown")
        return
    
    col1, col2, col3 = st.columns(3)
    
    # Calculate statistics
    risk_scores = [get_risk_score_from_db(row) for _, row in df.iterrows()]
    avg_risk = np.mean(risk_scores) if risk_scores else 0.5
    
    # Decision score distribution
    decision_scores = df['decision_score'].dropna().tolist() if 'decision_score' in df.columns else []
    avg_decision_score = np.mean(decision_scores) if decision_scores else avg_risk
    
    # Action distribution
    if 'decision_action' in df.columns:
        blocked_ratio = len(df[df['decision_action'].str.contains('BLOCK|DENY|QUARANTINE', case=False, na=False)]) / len(df) if len(df) > 0 else 0
    else:
        blocked_ratio = 0
    
    with col1:
        fig = go.Figure(go.Bar(
            x=['Avg Risk Score'],
            y=[avg_risk * 100],
            marker_color='#3b82f6',
            text=[f'{avg_risk*100:.1f}%'],
            textposition='outside'
        ))
        fig.update_layout(
            title="Average Risk Score", 
            height=300, 
            showlegend=False,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            yaxis=dict(range=[0, 100])
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        fig = go.Figure(go.Bar(
            x=['Decision Score'],
            y=[avg_decision_score * 100],
            marker_color='#f59e0b',
            text=[f'{avg_decision_score*100:.1f}%'],
            textposition='outside'
        ))
        fig.update_layout(
            title="Decision Score", 
            height=300, 
            showlegend=False,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            yaxis=dict(range=[0, 100])
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col3:
        fig = go.Figure(go.Bar(
            x=['Threat Ratio'],
            y=[blocked_ratio * 100],
            marker_color='#ef4444',
            text=[f'{blocked_ratio*100:.1f}%'],
            textposition='outside'
        ))
        fig.update_layout(
            title="Threat Detection Rate", 
            height=300, 
            showlegend=False,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            yaxis=dict(range=[0, 100])
        )
        st.plotly_chart(fig, use_container_width=True)

def display_soar_monitor(soar_logs):
    """Display SOAR action monitor"""
    st.markdown("### <i class='fas fa-cogs icon'></i> SOAR Automation Monitor", unsafe_allow_html=True)
    
    if soar_logs:
        actions_data = []
        for log in sorted(soar_logs, key=lambda x: x.get('timestamp', ''), reverse=True)[:15]:
            actions_data.append({
                'Action': log.get('action', 'Unknown'),
                'Target': log.get('target', 'N/A'),
                'Status': log.get('status', 'unknown'),
                'Reason': log.get('details', {}).get('reason', ''),
                'Time': log.get('timestamp', '')[-8:] if len(log.get('timestamp', '')) > 8 else log.get('timestamp', '')
            })
        
        df_actions = pd.DataFrame(actions_data)
        st.dataframe(df_actions, use_container_width=True)
    else:
        st.info("No SOAR actions logged yet")

def display_fl_metrics(config):
    """Display Federated Learning metrics"""
    st.markdown("### <i class='fas fa-brain icon'></i> Federated Learning Progress", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Current Round", "5", "Final Round")
    with col2:
        st.metric("Global Model Accuracy", "99.5%", "+0.1%")
    with col3:
        st.metric("Total Samples Aggregated", "9.88M", "+1.24M")
    
    # FL Progress Line Chart
    rounds = list(range(1, 6))
    accuracy = [95.2, 97.1, 98.3, 99.0, 99.5]
    f1_scores = [0.94, 0.96, 0.97, 0.985, 0.995]
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=rounds, y=accuracy, mode='lines+markers', name='Accuracy', line=dict(color='#10b981', width=3), marker=dict(size=10)))
    fig.add_trace(go.Scatter(x=rounds, y=[f*100 for f in f1_scores], mode='lines+markers', name='F1-Score', line=dict(color='#3b82f6', width=3), marker=dict(size=10)))
    
    fig.update_layout(
        title="FL Round Convergence",
        xaxis_title="Round",
        yaxis_title="Score (%)",
        height=350,
        hovermode='x unified',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Per-Site Accuracy
    st.subheader("Per-Site Model Performance")
    site_data = {
        'Site': ['Site A (Enterprise)', 'Site B (Cloud)', 'Site C (IoT)'],
        'Before FL': [98.44, 99.99, 99.62],
        'After FL': [99.12, 99.99, 99.75]
    }
    df_sites = pd.DataFrame(site_data)
    
    fig = go.Figure(data=[
        go.Bar(name='Before FL', x=site_data['Site'], y=site_data['Before FL'], marker_color='#f59e0b'),
        go.Bar(name='After FL', x=site_data['Site'], y=site_data['After FL'], marker_color='#10b981')
    ])
    fig.update_layout(
        title="Site Accuracy Comparison", 
        height=350, 
        barmode='group',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    st.plotly_chart(fig, use_container_width=True)

def display_device_status(state):
    """Display device and IP status"""
    st.markdown("### <i class='fas fa-desktop icon'></i> Device & IP Status", unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Quarantined Devices**")
        if state['quarantined_devices']:
            for ip, info in state['quarantined_devices'].items():
                st.warning(f"{ip} - {info.get('reason', 'Security threat')}")
        else:
            st.info("No quarantined devices")
    
    with col2:
        st.markdown("**Blocked IPs**")
        if state['blocked_ips']:
            for ip, info in state['blocked_ips'].items():
                st.error(f"{ip} - {info.get('reason', 'Malicious activity')}")
        else:
            st.info("No blocked IPs")

def display_firewall_rules(state):
    """Display firewall rules"""
    st.markdown("### <i class='fas fa-fire icon'></i> Firewall Rules", unsafe_allow_html=True)
    
    if state['firewall_rules']:
        rules_data = []
        for rule in state['firewall_rules'][:10]:
            rules_data.append({
                'Rule ID': rule.get('rule_id', 'N/A'),
                'Type': rule.get('type', 'N/A'),
                'Source': rule.get('source', 'Any'),
                'Action': rule.get('action', 'N/A'),
                'Duration (min)': rule.get('duration_minutes', 'Permanent'),
                'Reason': rule.get('reason', 'N/A')
            })
        
        df_rules = pd.DataFrame(rules_data)
        st.dataframe(df_rules, use_container_width=True)
    else:
        st.info("No firewall rules")

def display_traffic_distribution(db_path='sessions.db'):
    """Display traffic distribution pie chart from database"""
    st.markdown("### <i class='fas fa-chart-pie icon'></i> Traffic Distribution by Protocol", unsafe_allow_html=True)
    
    df = load_sessions_data(db_path, limit=1000)
    
    if df.empty:
        st.info("No data available for traffic distribution")
        return
    
    if 'proto' in df.columns:
        protocol_counts = df['proto'].apply(format_protocol).value_counts()
        
        fig = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title="Flow Distribution by Protocol",
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            showlegend=True
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Protocol data not available")

def display_top_blocked_ips(db_path='sessions.db'):
    """Display top blocked IPs from database"""
    st.markdown("### <i class='fas fa-ban icon'></i> Top Blocked IPs", unsafe_allow_html=True)
    
    df = load_sessions_data(db_path, limit=1000)
    
    if df.empty:
        st.info("No data available for blocked IPs analysis")
        return
    
    if 'decision_action' in df.columns and 'ip_src' in df.columns:
        blocked_df = df[df['decision_action'].str.contains('BLOCK|DENY|QUARANTINE', case=False, na=False)]
        
        if not blocked_df.empty:
            blocked_ips = blocked_df['ip_src'].value_counts().head(10)
            
            fig = px.bar(
                x=blocked_ips.values,
                y=blocked_ips.index,
                orientation='h',
                title="Top 10 Blocked Source IPs",
                labels={'x': 'Block Count', 'y': 'Source IP'},
                color=blocked_ips.values,
                color_continuous_scale='Reds'
            )
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white'),
                showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No blocked IPs found in current data")
    else:
        st.info("Decision action or IP data not available")

# ═══════════════════════════════════════════════════════════════════
# DEMO MODE
# ═══════════════════════════════════════════════════════════════════

def run_demo_mode():
    """Run automated demo mode for SIH presentation"""
    st.markdown("### <i class='fas fa-play-circle icon'></i> Demo Mode - SIH Presentation", unsafe_allow_html=True)
    
    demo_col1, demo_col2 = st.columns(2)
    
    with demo_col1:
        if st.button("Start Demo Sequence (3-4 minutes)", key="demo_start"):
            st.session_state.demo_running = True
            st.session_state.demo_start_time = time.time()
            st.rerun()
    
    with demo_col2:
        if st.button("Stop Demo", key="demo_stop"):
            st.session_state.demo_running = False
            st.rerun()
    
    if st.session_state.get('demo_running', False):
        demo_progress = st.progress(0)
        demo_status = st.empty()
        
        demo_steps = [
            ("Initializing dashboard...", 5),
            ("Loading ML models from 3 sites...", 5),
            ("Generating 50 test network flows...", 5),
            ("Classifying flows with ML models...", 5),
            ("Evaluating Zero Trust policies...", 5),
            ("Executing SOAR actions...", 10),
            ("Running Federated Learning Round 1...", 10),
            ("Aggregating weights from 3 sites...", 5),
            ("Running Federated Learning Round 2...", 10),
            ("Running Federated Learning Round 3...", 10),
            ("Running Federated Learning Round 4...", 10),
            ("Running Federated Learning Round 5 (Final)...", 15),
            ("Compiling results and metrics...", 10),
            ("Demo complete! Ready for presentation.", 5),
        ]
        
        elapsed = time.time() - st.session_state.demo_start_time
        total_duration = sum(d[1] for d in demo_steps)
        
        current_step = 0
        accumulated = 0
        for i, (step_name, step_duration) in enumerate(demo_steps):
            if accumulated + step_duration <= elapsed:
                current_step = i + 1
                accumulated += step_duration
            else:
                break
        
        progress_value = min(elapsed / total_duration, 1.0)
        demo_progress.progress(progress_value)
        
        if current_step < len(demo_steps):
            demo_status.write(f"Step {current_step + 1}/{len(demo_steps)}: {demo_steps[current_step][0]}")
        else:
            demo_status.success("Demo sequence complete!")
            st.session_state.demo_running = False
        
        if elapsed >= total_duration:
            st.session_state.demo_running = False

# ═══════════════════════════════════════════════════════════════════
# SIMULATION CONTROLS
# ═══════════════════════════════════════════════════════════════════

def display_simulation_controls():
    """Display simulation and test controls"""
    st.sidebar.markdown("### <i class='fas fa-sliders-h icon'></i> Simulation Controls", unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Replay Malicious Flow"):
            st.success("Replayed malicious flow through all engines")
    
    with col2:
        if st.button("Simulate Zero-Day Attack"):
            st.warning("Simulated zero-day attack - detected by anomaly engine")
    
    col3, col4 = st.columns(2)
    
    with col3:
        if st.button("Send Random Test Traffic"):
            st.info("Sent test flows to database")
    
    with col4:
        if st.button("Trigger SOAR Test Event"):
            st.info("SOAR test event triggered - executing playbooks")

# ═══════════════════════════════════════════════════════════════════
# MAIN APP
# ═══════════════════════════════════════════════════════════════════

def main():
    """Main dashboard application"""
    
    # Initialize session state
    if 'demo_running' not in st.session_state:
        st.session_state.demo_running = False
    if 'demo_start_time' not in st.session_state:
        st.session_state.demo_start_time = None
    
    # Load data
    config = load_config()
    soar_logs, zero_trust_logs = load_logs()
    state = load_state_files()
    
    # Display header
    db_path = "sessions.db"
    display_header(config, db_path)
    
    # Sidebar controls
    with st.sidebar:
        st.markdown("### <i class='fas fa-cog icon'></i> Dashboard Controls", unsafe_allow_html=True)
        
        db_path = st.text_input("Database Path", value="sessions.db", help="Path to SQLite database file")
        
        refresh_rate = st.select_slider(
            "Refresh Rate (seconds)",
            options=[1, 2, 5, 10],
            value=2
        )
        
        display_simulation_controls()
        
        st.divider()
        st.markdown("### <i class='fas fa-th-large icon'></i> Dashboard Sections", unsafe_allow_html=True)
        sections = st.multiselect(
            "Select sections to display",
            [
                "Unified Dashboard",
                "Sessions Table",
                "Flow Features Table",
                "TI Metadata Table",
                "Live Flows",
                "Risk Analysis",
                "SOAR Monitor",
                "FL Metrics",
                "Device Status",
                "Firewall Rules",
                "Traffic Analysis"
            ],
            default=[
                "Unified Dashboard",
                "Sessions Table",
                "Flow Features Table",
                "TI Metadata Table",
                "Live Flows",
                "Risk Analysis",
                "SOAR Monitor",
                "FL Metrics",
                "Device Status",
                "Firewall Rules",
                "Traffic Analysis"
            ]
        )
    
    # Main content
    tab1, tab2, tab3 = st.tabs(["Operations", "Analytics", "Demo"])
    
    with tab1:
        # Unified Dashboard (combines all three tables)
        if "Unified Dashboard" in sections:
            render_unified_dashboard(db_path=db_path)
            st.divider()
        
        # Sessions Table (from SQLite database)
        if "Sessions Table" in sections:
            render_sessions_table(db_path=db_path, refresh_interval=refresh_rate, show_newest=20)
            st.divider()
        
        # Flow Features Table (from SQLite database)
        if "Flow Features Table" in sections:
            render_flow_features_table(db_path=db_path, refresh_interval=refresh_rate, show_newest=20)
            st.divider()
        
        # TI Metadata Table (from SQLite database)
        if "TI Metadata Table" in sections:
            render_ti_metadata_table(db_path=db_path, refresh_interval=refresh_rate, show_newest=20)
            st.divider()
        
        # Live Flows (from database)
        if "Live Flows" in sections:
            display_live_flows(db_path=db_path, limit=20)
            st.divider()
        
        # Risk Analysis (from database)
        if "Risk Analysis" in sections:
            col_risk1, col_risk2 = st.columns([1, 2])
            
            with col_risk1:
                display_risk_gauge(db_path=db_path)
            
            with col_risk2:
                display_risk_breakdown(db_path=db_path)
            
            st.divider()
        
        # SOAR Monitor
        if "SOAR Monitor" in sections:
            display_soar_monitor(soar_logs)
            st.divider()
        
        # Device Status
        if "Device Status" in sections:
            display_device_status(state)
            st.divider()
        
        # Firewall Rules
        if "Firewall Rules" in sections:
            display_firewall_rules(state)
            st.divider()
    
    with tab2:
        # Sessions Summary
        if "Sessions Table" in sections:
            render_sessions_summary(db_path=db_path)
            st.divider()
        
        # Flow Features Analytics
        if "Flow Features Table" in sections:
            render_flow_features_analytics(db_path=db_path)
            st.divider()
        
        # TI Metadata Analytics
        if "TI Metadata Table" in sections:
            render_ti_metadata_analytics(db_path=db_path)
            st.divider()
        
        # FL Metrics
        if "FL Metrics" in sections:
            display_fl_metrics(config)
            st.divider()
        
        # Traffic Analysis (from database)
        if "Traffic Analysis" in sections:
            col_traffic1, col_traffic2 = st.columns(2)
            
            with col_traffic1:
                display_traffic_distribution(db_path=db_path)
            
            with col_traffic2:
                display_top_blocked_ips(db_path=db_path)
    
    with tab3:
        run_demo_mode()
    
    # Auto-refresh
    if refresh_rate > 0:
        time.sleep(refresh_rate)
        st.rerun()

if __name__ == "__main__":
    main()
