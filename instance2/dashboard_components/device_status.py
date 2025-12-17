"""
Device Status Component
Display device quarantine and IP block status
"""

import streamlit as st
import pandas as pd

def render_quarantined_devices(quarantined_devices):
    """Render quarantined devices"""
    
    st.subheader("Quarantined Devices")
    
    if not quarantined_devices:
        st.info("No devices currently quarantined")
        return
    
    device_data = []
    for ip, info in quarantined_devices.items():
        device_data.append({
            'Device IP': ip,
            'Quarantine Time': info.get('quarantined_at', 'N/A')[-8:],
            'Original Zone': info.get('original_zone', 'N/A'),
            'Current Zone': info.get('current_zone', 'N/A'),
            'Reason': info.get('reason', 'N/A')[:40]
        })
    
    df = pd.DataFrame(device_data)
    st.dataframe(df, use_container_width=True)

def render_blocked_ips(blocked_ips):
    """Render blocked IPs"""
    
    st.subheader("Blocked IPs")
    
    if not blocked_ips:
        st.info("No IPs currently blocked")
        return
    
    ip_data = []
    for ip, info in blocked_ips.items():
        ip_data.append({
            'Blocked IP': ip,
            'Blocked At': info.get('blocked_at', 'N/A')[-8:],
            'Expires': info.get('blocked_until', 'N/A')[-8:],
            'Duration (min)': info.get('duration_minutes', 'N/A'),
            'Reason': info.get('reason', 'N/A')[:40]
        })
    
    df = pd.DataFrame(ip_data)
    st.dataframe(df, use_container_width=True)

def render_device_profiles(device_profiles):
    """Render device behavioral profiles"""
    
    st.subheader("Device Behavioral Profiles")
    
    if not device_profiles:
        st.info("No device profiles available")
        return
    
    profile_data = []
    for ip, profile in list(device_profiles.items())[:10]:
        profile_data.append({
            'Device IP': ip,
            'Zone': profile.get('zone', 'N/A'),
            'Risk Score': f"{profile.get('risk_score', 0):.2f}",
            'Last Seen': profile.get('last_seen', 'N/A')[-8:],
            'Status': 'Normal' if profile.get('risk_score', 0) < 0.5 else 'Suspicious'
        })
    
    df = pd.DataFrame(profile_data)
    st.dataframe(df, use_container_width=True)

def render_zone_distribution(device_profiles):
    """Render devices by zone"""
    
    st.subheader("Zone Distribution")
    
    zone_counts = {}
    for ip, profile in device_profiles.items():
        zone = profile.get('zone', 'Unknown')
        zone_counts[zone] = zone_counts.get(zone, 0) + 1
    
    if zone_counts:
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Enterprise", zone_counts.get('Enterprise', 0))
        with col2:
            st.metric("Cloud", zone_counts.get('Cloud', 0))
        with col3:
            st.metric("IoT", zone_counts.get('IoT', 0))
        with col4:
            st.metric("Quarantine", zone_counts.get('Quarantine', 0))
    else:
        st.info("No zone data available")

def render_device_status_summary(state):
    """Render overall device status summary"""
    
    col1, col2, col3 = st.columns(3)
    
    quarantined_count = len(state.get('quarantined_devices', {}))
    blocked_count = len(state.get('blocked_ips', {}))
    total_devices = len(state.get('device_profiles', {}))
    
    with col1:
        st.metric("Total Devices", total_devices)
    
    with col2:
        st.metric("Quarantined", quarantined_count)
    
    with col3:
        st.metric("Blocked IPs", blocked_count)
