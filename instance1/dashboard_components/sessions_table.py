"""
Sessions Table Component
Displays real-time network sessions from SQLite database
Shows newest 20 rows at top, older rows below with auto-refresh
"""

import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import time
from pathlib import Path

def get_sessions_data(db_path='session.db', limit=None):
    """
    Fetch sessions data from SQLite database
    
    Args:
        db_path: Path to SQLite database file
        limit: Maximum number of rows to fetch (None for all)
    
    Returns:
        DataFrame with sessions data, sorted by last_ts descending (newest first)
    """
    try:
        conn = sqlite3.connect(db_path)
        
        # Build query - order by last_ts descending to get newest first
        # Include all columns from the schema
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
                sttl,
                dttl,
                Spkts,
                Dpkts,
                swin,
                dwin,
                stcpb,
                dtcpb,
                smeansz,
                dmeansz,
                Sintpkt,
                Dintpkt,
                state,
                is_sm_ips_ports,
                syn_count,
                fin_count,
                rst_count,
                decision_action,
                decision_label,
                decision_score,
                decision_tier,
                decision_reason
            FROM sessions
            ORDER BY last_ts DESC
        """
        
        if limit:
            query += f" LIMIT {limit}"
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        return df
    
    except sqlite3.Error as e:
        st.error(f"Database error: {e}")
        return pd.DataFrame()
    except FileNotFoundError:
        st.warning(f"Database file '{db_path}' not found. Waiting for data...")
        return pd.DataFrame()
    except Exception as e:
        st.error(f"Error reading sessions: {e}")
        return pd.DataFrame()

def format_timestamp(ts):
    """Format Unix timestamp to readable format"""
    try:
        if pd.isna(ts):
            return "N/A"
        dt = datetime.fromtimestamp(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return str(ts)

def format_bytes(bytes_val):
    """Format bytes to human-readable format"""
    try:
        if pd.isna(bytes_val):
            return "0 B"
        bytes_val = int(bytes_val)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} TB"
    except:
        return str(bytes_val)

def color_decision_action(val):
    """Apply color coding based on decision action"""
    if pd.isna(val):
        return ''
    
    val_str = str(val).upper()
    if 'ALLOW' in val_str or 'PERMIT' in val_str:
        return 'background-color: #90EE90; color: black'
    elif 'ALERT' in val_str or 'WARN' in val_str:
        return 'background-color: #FFD700; color: black'
    elif 'BLOCK' in val_str or 'DENY' in val_str:
        return 'background-color: #FF8C00; color: white'
    elif 'QUARANTINE' in val_str or 'ISOLATE' in val_str:
        return 'background-color: #FF0000; color: white'
    else:
        return ''

def color_decision_tier(val):
    """Apply color coding based on decision tier"""
    if pd.isna(val):
        return ''
    
    val_str = str(val).upper()
    if 'LOW' in val_str:
        return 'background-color: #90EE90; color: black'
    elif 'MEDIUM' in val_str or 'MODERATE' in val_str:
        return 'background-color: #FFD700; color: black'
    elif 'HIGH' in val_str:
        return 'background-color: #FF8C00; color: white'
    elif 'CRITICAL' in val_str:
        return 'background-color: #FF0000; color: white'
    else:
        return ''

def render_sessions_table(db_path='session.db', refresh_interval=2, show_newest=20):
    """
    Render sessions table with auto-refresh
    
    Args:
        db_path: Path to SQLite database
        refresh_interval: Refresh interval in seconds
        show_newest: Number of newest rows to highlight at top
    """
    
    st.subheader("Network Sessions (Real-Time)")
    
    # Display database status
    db_exists = Path(db_path).exists()
    if db_exists:
        st.success(f"Connected to database: {db_path}")
    else:
        st.warning(f"Database not found: {db_path}. Waiting for data...")
    
    # Fetch all data
    df = get_sessions_data(db_path)
    
    if df.empty:
        st.info("No sessions data available yet. Waiting for new data...")
        return
    
    # Display statistics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Sessions", len(df))
    
    with col2:
        if 'decision_action' in df.columns:
            allowed = len(df[df['decision_action'].str.contains('ALLOW|PERMIT', case=False, na=False)])
            st.metric("Allowed", allowed)
        else:
            st.metric("Allowed", "N/A")
    
    with col3:
        if 'decision_action' in df.columns:
            blocked = len(df[df['decision_action'].str.contains('BLOCK|DENY|QUARANTINE', case=False, na=False)])
            st.metric("Blocked", blocked)
        else:
            st.metric("Blocked", "N/A")
    
    with col4:
        if 'last_ts' in df.columns and not df['last_ts'].isna().all():
            latest_ts = df['last_ts'].max()
            latest_time = format_timestamp(latest_ts)
            st.metric("Last Update", latest_time.split()[1] if ' ' in latest_time else latest_time)
        else:
            st.metric("Last Update", "N/A")
    
    st.divider()
    
    # Prepare data for display
    display_df = df.copy()
    
    # Format timestamps
    if 'first_ts' in display_df.columns:
        display_df['first_ts'] = display_df['first_ts'].apply(format_timestamp)
    if 'last_ts' in display_df.columns:
        display_df['last_ts'] = display_df['last_ts'].apply(format_timestamp)
    
    # Format bytes
    if 'bytes_fwd' in display_df.columns:
        display_df['bytes_fwd'] = display_df['bytes_fwd'].apply(format_bytes)
    if 'bytes_rev' in display_df.columns:
        display_df['bytes_rev'] = display_df['bytes_rev'].apply(format_bytes)
    
    # Rename columns for better display
    column_mapping = {
        'flow_key': 'Flow Key',
        'ip_src': 'Source IP',
        'ip_dst': 'Dest IP',
        'sport': 'Src Port',
        'dport': 'Dest Port',
        'proto': 'Protocol',
        'first_ts': 'First Seen',
        'last_ts': 'Last Seen',
        'dur': 'Duration',
        'pkt_count': 'Total Pkts',
        'pkts_fwd': 'Pkts Fwd',
        'pkts_rev': 'Pkts Rev',
        'bytes_fwd': 'Bytes Fwd',
        'bytes_rev': 'Bytes Rev',
        'sbytes': 'Src Bytes',
        'dbytes': 'Dst Bytes',
        'sttl': 'Src TTL',
        'dttl': 'Dst TTL',
        'Spkts': 'Src Pkts',
        'Dpkts': 'Dst Pkts',
        'swin': 'Src Win',
        'dwin': 'Dst Win',
        'stcpb': 'Src TCPB',
        'dtcpb': 'Dst TCPB',
        'smeansz': 'Src Mean Sz',
        'dmeansz': 'Dst Mean Sz',
        'Sintpkt': 'Src Int Pkt',
        'Dintpkt': 'Dst Int Pkt',
        'state': 'State',
        'is_sm_ips_ports': 'Same IP/Port',
        'syn_count': 'SYN',
        'fin_count': 'FIN',
        'rst_count': 'RST',
        'decision_action': 'Action',
        'decision_label': 'Label',
        'decision_score': 'Score',
        'decision_tier': 'Tier',
        'decision_reason': 'Reason'
    }
    
    display_df = display_df.rename(columns=column_mapping)
    
    # Select columns to display (in order) - key columns for main view
    display_columns = [
        'Flow Key', 'Source IP', 'Dest IP', 'Src Port', 'Dest Port', 'Protocol',
        'First Seen', 'Last Seen', 'Duration', 'Total Pkts', 'Pkts Fwd', 'Pkts Rev',
        'Bytes Fwd', 'Bytes Rev', 'State', 'SYN', 'FIN', 'RST',
        'Action', 'Label', 'Score', 'Tier', 'Reason'
    ]
    
    # Filter to only existing columns
    display_columns = [col for col in display_columns if col in display_df.columns]
    display_df = display_df[display_columns]
    
    # Split into newest and older rows
    newest_df = display_df.head(show_newest)
    older_df = display_df.iloc[show_newest:]
    
    # Display newest rows section
    st.markdown(f"### Newest {show_newest} Sessions")
    
    if not newest_df.empty:
        # Apply styling
        styled_newest = newest_df.style.applymap(
            color_decision_action, subset=['Action'] if 'Action' in newest_df.columns else []
        ).applymap(
            color_decision_tier, subset=['Tier'] if 'Tier' in newest_df.columns else []
        )
        
        st.dataframe(
            styled_newest,
            use_container_width=True,
            height=400
        )
    else:
        st.info("No new sessions")
    
    # Display older rows section (scrollable)
    if not older_df.empty:
        st.markdown(f"### Older Sessions ({len(older_df)} rows)")
        st.caption("Scroll down to view older sessions")
        
        # Apply styling
        styled_older = older_df.style.applymap(
            color_decision_action, subset=['Action'] if 'Action' in older_df.columns else []
        ).applymap(
            color_decision_tier, subset=['Tier'] if 'Tier' in older_df.columns else []
        )
        
        st.dataframe(
            styled_older,
            use_container_width=True,
            height=600
        )
    else:
        st.info("No older sessions to display")
    
    # Auto-refresh indicator
    st.caption(f"Auto-refreshing every {refresh_interval} seconds...")
    
    # Store last row count for change detection
    if 'last_session_count' not in st.session_state:
        st.session_state.last_session_count = len(df)
    
    if len(df) != st.session_state.last_session_count:
        st.session_state.last_session_count = len(df)
        st.rerun()

def render_sessions_summary(db_path='session.db'):
    """Render summary statistics for sessions"""
    
    df = get_sessions_data(db_path, limit=1000)  # Get recent 1000 for summary
    
    if df.empty:
        return
    
    st.subheader("Sessions Summary")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Top Source IPs**")
        if 'ip_src' in df.columns:
            top_src = df['ip_src'].value_counts().head(10)
            st.dataframe(pd.DataFrame({
                'Source IP': top_src.index,
                'Session Count': top_src.values
            }), use_container_width=True, hide_index=True)
    
    with col2:
        st.markdown("**Top Destination IPs**")
        if 'ip_dst' in df.columns:
            top_dst = df['ip_dst'].value_counts().head(10)
            st.dataframe(pd.DataFrame({
                'Dest IP': top_dst.index,
                'Session Count': top_dst.values
            }), use_container_width=True, hide_index=True)
    
    # Protocol distribution
    if 'proto' in df.columns:
        st.markdown("**Protocol Distribution**")
        proto_counts = df['proto'].value_counts()
        st.bar_chart(proto_counts)
    
    # Decision action distribution
    if 'decision_action' in df.columns:
        st.markdown("**Decision Action Distribution**")
        action_counts = df['decision_action'].value_counts()
        st.bar_chart(action_counts)

