"""
Rules Viewer Component
Display and search firewall rules
"""

import streamlit as st
import pandas as pd

def render_firewall_rules(firewall_rules):
    """Render firewall rules table"""
    
    st.subheader("Active Firewall Rules")
    
    if not firewall_rules:
        st.info("No firewall rules configured")
        return
    
    rules_data = []
    for rule in sorted(firewall_rules, key=lambda x: x.get('rule_id', 0), reverse=True)[:20]:
        rules_data.append({
            'ID': rule.get('rule_id', 'N/A'),
            'Type': rule.get('type', 'N/A'),
            'Source': rule.get('source', 'Any'),
            'Action': rule.get('action', 'N/A')[:30],
            'Duration': f"{rule.get('duration_minutes', '∞')} min",
            'Reason': rule.get('reason', 'N/A')[:30],
            'Added': rule.get('added_at', 'N/A')[-8:]
        })
    
    df = pd.DataFrame(rules_data)
    st.dataframe(df, use_container_width=True)

def render_rules_statistics(firewall_rules):
    """Render firewall rules statistics"""
    
    col1, col2, col3, col4 = st.columns(4)
    
    total_rules = len(firewall_rules)
    drop_rules = sum(1 for r in firewall_rules if r.get('type') == 'DROP')
    drop_all_rules = sum(1 for r in firewall_rules if r.get('type') == 'DROP_ALL')
    
    with col1:
        st.metric("Total Rules", total_rules)
    
    with col2:
        st.metric("DROP Rules", drop_rules)
    
    with col3:
        st.metric("DROP_ALL Rules", drop_all_rules)
    
    with col4:
        st.metric("Other Rules", total_rules - drop_rules - drop_all_rules)

def render_rules_search(firewall_rules):
    """Render rules search and filter"""
    
    st.subheader("Search Rules")
    
    col1, col2 = st.columns(2)
    
    with col1:
        search_ip = st.text_input("Search by Source IP", "")
    
    with col2:
        filter_type = st.selectbox(
            "Filter by Type",
            ["All", "DROP", "DROP_ALL"],
            key="rule_type_filter"
        )
    
    # Filter rules
    filtered_rules = firewall_rules
    
    if search_ip:
        filtered_rules = [r for r in filtered_rules if search_ip in r.get('source', '')]
    
    if filter_type != "All":
        filtered_rules = [r for r in filtered_rules if r.get('type') == filter_type]
    
    if filtered_rules:
        rules_data = []
        for rule in filtered_rules[:10]:
            rules_data.append({
                'ID': rule.get('rule_id', 'N/A'),
                'Source': rule.get('source', 'Any'),
                'Type': rule.get('type', 'N/A'),
                'Action': rule.get('action', 'N/A'),
                'Reason': rule.get('reason', 'N/A')
            })
        
        df = pd.DataFrame(rules_data)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No rules match your search criteria")

def render_rule_timeline(firewall_rules):
    """Render rules added over time"""
    
    st.subheader("Rules Added Timeline")
    
    # Group rules by time
    time_groups = {}
    for rule in firewall_rules:
        timestamp = rule.get('added_at', 'Unknown')
        if 'T' in timestamp:
            time_key = timestamp.split('T')[1][:5]  # HH:MM
        else:
            time_key = 'Unknown'
        
        time_groups[time_key] = time_groups.get(time_key, 0) + 1
    
    if time_groups:
        df_timeline = pd.DataFrame(
            list(time_groups.items()),
            columns=['Time', 'Rules Added']
        ).sort_values('Time')
        
        st.bar_chart(df_timeline.set_index('Time'))
    else:
        st.info("No timeline data available")
