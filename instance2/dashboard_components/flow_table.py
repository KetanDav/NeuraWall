"""
Flow Table Component
Displays real-time network flows with color-coded decisions
"""

import streamlit as st
import pandas as pd
from datetime import datetime

def render_flow_table(flows):
    """Render live traffic flow table with color coding"""
    
    df_data = []
    for flow in sorted(flows, key=lambda x: x['timestamp'], reverse=True)[:20]:
        # Calculate risk score
        risk_score = 0.6 * flow['model_prob'] + 0.25 * flow['anomaly_score'] + 0.15 * 0.1
        
        # Get decision
        if risk_score < 0.30:
            decision = "ALLOW"
        elif risk_score < 0.60:
            decision = "ALERT"
        elif risk_score < 0.85:
            decision = "BLOCK"
        else:
            decision = "QUARANTINE"
        
        # Map to SOAR action
        actions = {
            "ALLOW": "Permit",
            "ALERT": "Sandbox",
            "BLOCK": "Block IP",
            "QUARANTINE": "Quarantine"
        }
        
        df_data.append({
            'Flow ID': flow['flow_id'][:10],
            'Source IP': flow['src_ip'],
            'Dest IP': flow['dst_ip'],
            'Protocol': flow['protocol'],
            'ML Score': f"{flow['model_prob']*100:.1f}%",
            'Anomaly': f"{flow['anomaly_score']:.2f}",
            'Risk': f"{risk_score:.2f}",
            'Decision': decision,
            'Action': actions.get(decision, "?"),
            'Timestamp': flow['timestamp'].split('T')[1][:8] if 'T' in flow['timestamp'] else flow['timestamp']
        })
    
    df = pd.DataFrame(df_data)
    
    # Apply color coding
    def highlight_decision(val):
        if val == 'ALLOW':
            return 'background-color: #90EE90'
        elif val == 'ALERT':
            return 'background-color: #FFD700'
        elif val == 'BLOCK':
            return 'background-color: #FF8C00'
        elif val == 'QUARANTINE':
            return 'background-color: #FF0000; color: white'
        return ''
    
    styled_df = df.style.applymap(lambda val: highlight_decision(val), subset=['Decision'])
    return styled_df

def display_flow_metrics(flows):
    """Display flow statistics and metrics"""
    
    col1, col2, col3, col4 = st.columns(4)
    
    total_flows = len(flows)
    
    # Count decisions
    allow_count = sum(1 for f in flows if 0.6 * f['model_prob'] + 0.25 * f['anomaly_score'] < 0.30)
    alert_count = sum(1 for f in flows if 0.30 <= (0.6 * f['model_prob'] + 0.25 * f['anomaly_score']) < 0.60)
    block_count = sum(1 for f in flows if 0.60 <= (0.6 * f['model_prob'] + 0.25 * f['anomaly_score']) < 0.85)
    quarantine_count = sum(1 for f in flows if (0.6 * f['model_prob'] + 0.25 * f['anomaly_score']) >= 0.85)
    
    with col1:
        st.metric("Total Flows", total_flows)
    
    with col2:
        st.metric("Allowed", allow_count, f"{allow_count/total_flows*100:.1f}%")
    
    with col3:
        st.metric("Blocked", block_count + quarantine_count, f"{(block_count + quarantine_count)/total_flows*100:.1f}%")
    
    with col4:
        st.metric("Avg Risk", f"{sum(0.6 * f['model_prob'] + 0.25 * f['anomaly_score'] for f in flows) / total_flows:.2f}")
