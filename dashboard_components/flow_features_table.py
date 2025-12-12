"""
Flow Features Table Component
Displays flow features data from SQLite database
"""

import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
from pathlib import Path
import plotly.express as px
import plotly.graph_objects as go

def get_flow_features_data(db_path='session.db', limit=None):
    """
    Fetch flow features data from SQLite database
    
    Args:
        db_path: Path to SQLite database file
        limit: Maximum number of rows to fetch (None for all)
    
    Returns:
        DataFrame with flow features data
    """
    try:
        conn = sqlite3.connect(db_path)
        
        query = """
            SELECT 
                flow_key,
                sport,
                dsport,
                proto,
                state,
                dur,
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
                Stime,
                Ltime,
                is_sm_ips_ports
            FROM flow_features
            ORDER BY Ltime DESC
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
        st.error(f"Error reading flow features: {e}")
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

def render_flow_features_table(db_path='session.db', refresh_interval=2, show_newest=20):
    """
    Render flow features table with auto-refresh
    
    Args:
        db_path: Path to SQLite database
        refresh_interval: Refresh interval in seconds
        show_newest: Number of newest rows to highlight at top
    """
    
    st.subheader("Flow Features (Real-Time)")
    
    # Display database status
    db_exists = Path(db_path).exists()
    if db_exists:
        st.success(f"Connected to database: {db_path}")
    else:
        st.warning(f"Database not found: {db_path}. Waiting for data...")
    
    # Fetch all data
    df = get_flow_features_data(db_path)
    
    if df.empty:
        st.info("No flow features data available yet. Waiting for new data...")
        return
    
    # Display statistics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Flows", len(df))
    
    with col2:
        if 'proto' in df.columns:
            unique_protos = df['proto'].nunique()
            st.metric("Unique Protocols", unique_protos)
        else:
            st.metric("Unique Protocols", "N/A")
    
    with col3:
        if 'state' in df.columns:
            unique_states = df['state'].nunique()
            st.metric("Unique States", unique_states)
        else:
            st.metric("Unique States", "N/A")
    
    with col4:
        if 'Ltime' in df.columns and not df['Ltime'].isna().all():
            latest_ts = df['Ltime'].max()
            latest_time = format_timestamp(latest_ts)
            st.metric("Last Update", latest_time.split()[1] if ' ' in latest_time else latest_time)
        else:
            st.metric("Last Update", "N/A")
    
    st.divider()
    
    # Prepare data for display
    display_df = df.copy()
    
    # Format timestamps
    if 'Stime' in display_df.columns:
        display_df['Stime'] = display_df['Stime'].apply(format_timestamp)
    if 'Ltime' in display_df.columns:
        display_df['Ltime'] = display_df['Ltime'].apply(format_timestamp)
    
    # Format bytes
    if 'sbytes' in display_df.columns:
        display_df['sbytes'] = display_df['sbytes'].apply(format_bytes)
    if 'dbytes' in display_df.columns:
        display_df['dbytes'] = display_df['dbytes'].apply(format_bytes)
    
    # Rename columns for better display
    column_mapping = {
        'flow_key': 'Flow Key',
        'sport': 'Src Port',
        'dsport': 'Dst Port',
        'proto': 'Protocol',
        'state': 'State',
        'dur': 'Duration',
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
        'Stime': 'Start Time',
        'Ltime': 'Last Time',
        'is_sm_ips_ports': 'Same IP/Port'
    }
    
    display_df = display_df.rename(columns=column_mapping)
    
    # Select columns to display
    display_columns = [
        'Flow Key', 'Src Port', 'Dst Port', 'Protocol', 'State', 'Duration',
        'Src Bytes', 'Dst Bytes', 'Src TTL', 'Dst TTL',
        'Src Pkts', 'Dst Pkts', 'Src Win', 'Dst Win',
        'Src Mean Sz', 'Dst Mean Sz', 'Start Time', 'Last Time', 'Same IP/Port'
    ]
    
    # Filter to only existing columns
    display_columns = [col for col in display_columns if col in display_df.columns]
    display_df = display_df[display_columns]
    
    # Split into newest and older rows
    newest_df = display_df.head(show_newest)
    older_df = display_df.iloc[show_newest:]
    
    # Display newest rows section
    st.markdown(f"### Newest {show_newest} Flow Features")
    
    if not newest_df.empty:
        st.dataframe(
            newest_df,
            use_container_width=True,
            height=400
        )
    else:
        st.info("No new flow features")
    
    # Display older rows section
    if not older_df.empty:
        st.markdown(f"### Older Flow Features ({len(older_df)} rows)")
        st.caption("Scroll down to view older flow features")
        
        st.dataframe(
            older_df,
            use_container_width=True,
            height=600
        )
    else:
        st.info("No older flow features to display")
    
    # Auto-refresh indicator
    st.caption(f"Auto-refreshing every {refresh_interval} seconds...")
    
    # Store last row count for change detection
    if 'last_flow_features_count' not in st.session_state:
        st.session_state.last_flow_features_count = len(df)
    
    if len(df) != st.session_state.last_flow_features_count:
        st.session_state.last_flow_features_count = len(df)
        st.rerun()

def render_flow_features_analytics(db_path='sessions.db'):
    """Render analytics and visualizations for flow features"""
    
    df = get_flow_features_data(db_path, limit=1000)  # Get recent 1000 for analytics
    
    if df.empty:
        st.info("No flow features data available for analytics")
        return
    
    st.subheader("Flow Features Analytics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Protocol distribution
        if 'proto' in df.columns:
            st.markdown("**Protocol Distribution**")
            proto_counts = df['proto'].value_counts().head(10)
            fig = px.bar(
                x=proto_counts.index,
                y=proto_counts.values,
                labels={'x': 'Protocol', 'y': 'Count'},
                title="Top 10 Protocols"
            )
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white')
            )
            st.plotly_chart(fig, use_container_width=True, key="ff_proto_distribution")
    
    with col2:
        # State distribution
        if 'state' in df.columns:
            st.markdown("**Connection State Distribution**")
            state_counts = df['state'].value_counts().head(10)
            fig = px.pie(
                values=state_counts.values,
                names=state_counts.index,
                title="Top 10 Connection States"
            )
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white')
            )
            st.plotly_chart(fig, use_container_width=True, key="ff_state_distribution")
    
    # Bytes distribution
    if 'sbytes' in df.columns and 'dbytes' in df.columns:
        st.markdown("**Bytes Distribution**")
        col3, col4 = st.columns(2)
        
        with col3:
            # Source bytes histogram
            fig = px.histogram(
                df,
                x='sbytes',
                nbins=50,
                title="Source Bytes Distribution",
                labels={'sbytes': 'Source Bytes', 'count': 'Frequency'}
            )
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white')
            )
            st.plotly_chart(fig, use_container_width=True, key="ff_sbytes_hist")
        
        with col4:
            # Destination bytes histogram
            fig = px.histogram(
                df,
                x='dbytes',
                nbins=50,
                title="Destination Bytes Distribution",
                labels={'dbytes': 'Destination Bytes', 'count': 'Frequency'}
            )
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white')
            )
            st.plotly_chart(fig, use_container_width=True, key="ff_dbytes_hist")
    
    # Duration vs Packets scatter
    if 'dur' in df.columns and 'Spkts' in df.columns:
        st.markdown("**Duration vs Packets Analysis**")
        fig = px.scatter(
            df.head(500),  # Limit for performance
            x='dur',
            y='Spkts',
            color='proto' if 'proto' in df.columns else None,
            title="Flow Duration vs Source Packets",
            labels={'dur': 'Duration (seconds)', 'Spkts': 'Source Packets'}
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        st.plotly_chart(fig, use_container_width=True, key="ff_dur_spkts_scatter")

