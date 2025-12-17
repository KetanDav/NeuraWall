"""
SOAR Panel Component
Displays SOAR automation actions and events
"""

import streamlit as st
import pandas as pd
from datetime import datetime

def render_soar_actions(soar_logs):
    """Render SOAR action log"""
    
    if not soar_logs:
        st.info("No SOAR actions logged yet")
        return
    
    actions_data = []
    for log in sorted(soar_logs, key=lambda x: x.get('timestamp', ''), reverse=True)[:20]:
        actions_data.append({
            'Time': log.get('timestamp', '')[-8:] if log.get('timestamp') else 'N/A',
            'Action': log.get('action', 'Unknown'),
            'Target': log.get('target', 'N/A'),
            'Status': 'Success' if log.get('status') == 'success' else 'Failed',
            'Details': log.get('details', {}).get('reason', ''),
        })
    
    df = pd.DataFrame(actions_data)
    
    # Apply color coding
    def color_status(val):
        if 'Success' in str(val):
            return 'background-color: #4ade80'
        else:
            return 'background-color: #f87171'
    
    styled_df = df.style.applymap(lambda val: color_status(val), subset=['Status'])
    st.dataframe(styled_df, use_container_width=True)

def render_soar_statistics(soar_logs):
    """Render SOAR action statistics"""
    
    if not soar_logs:
        st.info("No SOAR statistics available")
        return
    
    col1, col2, col3, col4 = st.columns(4)
    
    total_actions = len(soar_logs)
    successful = sum(1 for log in soar_logs if log.get('status') == 'success')
    failed = total_actions - successful
    
    # Count action types
    action_types = {}
    for log in soar_logs:
        action = log.get('action', 'Unknown')
        action_types[action] = action_types.get(action, 0) + 1
    
    most_common_action = max(action_types.items(), key=lambda x: x[1])[0] if action_types else 'N/A'
    
    with col1:
        st.metric("Total Actions", total_actions)
    
    with col2:
        st.metric("Successful", successful, f"{successful/total_actions*100:.1f}%")
    
    with col3:
        st.metric("Failed", failed, f"{failed/total_actions*100:.1f}%")
    
    with col4:
        st.metric("Most Common", most_common_action[:15])

def render_recent_alerts(soar_logs):
    """Render recent security alerts"""
    
    st.subheader("Recent Alerts")
    
    alerts = [log for log in soar_logs if log.get('action') in ['alert_security_team', 'quarantine_device', 'block_ip']]
    
    for alert in alerts[-5:]:
        timestamp = alert.get('timestamp', 'Unknown')[-8:]
        action = alert.get('action', 'Unknown')
        target = alert.get('target', 'Unknown')
        reason = alert.get('details', {}).get('reason', 'No reason provided')
        
        if action == 'quarantine_device':
            st.error(f"[Quarantine] {target} - {reason} ({timestamp})")
        elif action == 'block_ip':
            st.warning(f"[Block] {target} - {reason} ({timestamp})")
        else:
            st.info(f"[{action}] {target} - {reason} ({timestamp})")
