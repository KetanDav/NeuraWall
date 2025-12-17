"""
Threat Intelligence Metadata Table Component
Displays threat intelligence metadata from SQLite database
"""

import streamlit as st
import pandas as pd
import sqlite3
from pathlib import Path
import plotly.express as px

def get_ti_metadata_data(db_path='session.db', limit=None):
    """
    Fetch threat intelligence metadata from SQLite database
    
    Args:
        db_path: Path to SQLite database file
        limit: Maximum number of rows to fetch (None for all)
    
    Returns:
        DataFrame with TI metadata
    """
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
                http_host,
                http_path,
                url,
                tls_ja3,
                tls_sni
            FROM ti_metadata
            ORDER BY flow_key DESC
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
        st.error(f"Error reading TI metadata: {e}")
        return pd.DataFrame()

def render_ti_metadata_table(db_path='session.db', refresh_interval=2, show_newest=20):
    """
    Render threat intelligence metadata table with auto-refresh
    
    Args:
        db_path: Path to SQLite database
        refresh_interval: Refresh interval in seconds
        show_newest: Number of newest rows to highlight at top
    """
    
    st.subheader("Threat Intelligence Metadata (Real-Time)")
    
    # Display database status
    db_exists = Path(db_path).exists()
    if db_exists:
        st.success(f"Connected to database: {db_path}")
    else:
        st.warning(f"Database not found: {db_path}. Waiting for data...")
    
    # Fetch all data
    df = get_ti_metadata_data(db_path)
    
    if df.empty:
        st.info("No threat intelligence metadata available yet. Waiting for new data...")
        return
    
    # Display statistics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Records", len(df))
    
    with col2:
        if 'ip_src' in df.columns:
            unique_src_ips = df['ip_src'].nunique()
            st.metric("Unique Source IPs", unique_src_ips)
        else:
            st.metric("Unique Source IPs", "N/A")
    
    with col3:
        if 'http_host' in df.columns:
            http_records = df['http_host'].notna().sum()
            st.metric("HTTP Records", http_records)
        else:
            st.metric("HTTP Records", "N/A")
    
    with col4:
        if 'tls_sni' in df.columns:
            tls_records = df['tls_sni'].notna().sum()
            st.metric("TLS Records", tls_records)
        else:
            st.metric("TLS Records", "N/A")
    
    st.divider()
    
    # Prepare data for display
    display_df = df.copy()
    
    # Rename columns for better display
    column_mapping = {
        'flow_key': 'Flow Key',
        'ip_src': 'Source IP',
        'ip_dst': 'Dest IP',
        'sport': 'Src Port',
        'dport': 'Dest Port',
        'proto': 'Protocol',
        'http_host': 'HTTP Host',
        'http_path': 'HTTP Path',
        'url': 'URL',
        'tls_ja3': 'TLS JA3',
        'tls_sni': 'TLS SNI'
    }
    
    display_df = display_df.rename(columns=column_mapping)
    
    # Select columns to display
    display_columns = [
        'Flow Key', 'Source IP', 'Dest IP', 'Src Port', 'Dest Port', 'Protocol',
        'HTTP Host', 'HTTP Path', 'URL', 'TLS JA3', 'TLS SNI'
    ]
    
    # Filter to only existing columns
    display_columns = [col for col in display_columns if col in display_df.columns]
    display_df = display_df[display_columns]
    
    # Split into newest and older rows
    newest_df = display_df.head(show_newest)
    older_df = display_df.iloc[show_newest:]
    
    # Display newest rows section
    st.markdown(f"### Newest {show_newest} TI Records")
    
    if not newest_df.empty:
        st.dataframe(
            newest_df,
            use_container_width=True,
            height=400
        )
    else:
        st.info("No new TI metadata")
    
    # Display older rows section
    if not older_df.empty:
        st.markdown(f"### Older TI Records ({len(older_df)} rows)")
        st.caption("Scroll down to view older TI metadata")
        
        st.dataframe(
            older_df,
            use_container_width=True,
            height=600
        )
    else:
        st.info("No older TI metadata to display")
    
    # Auto-refresh indicator
    st.caption(f"Auto-refreshing every {refresh_interval} seconds...")
    
    # Store last row count for change detection
    if 'last_ti_metadata_count' not in st.session_state:
        st.session_state.last_ti_metadata_count = len(df)
    
    if len(df) != st.session_state.last_ti_metadata_count:
        st.session_state.last_ti_metadata_count = len(df)
        st.rerun()

def render_ti_metadata_analytics(db_path='session.db'):
    """Render analytics and visualizations for TI metadata"""
    
    df = get_ti_metadata_data(db_path, limit=1000)  # Get recent 1000 for analytics
    
    if df.empty:
        st.info("No TI metadata available for analytics")
        return
    
    st.subheader("Threat Intelligence Analytics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Top source IPs
        if 'ip_src' in df.columns:
            st.markdown("**Top Source IPs**")
            top_src = df['ip_src'].value_counts().head(10)
            fig = px.bar(
                x=top_src.values,
                y=top_src.index,
                orientation='h',
                labels={'x': 'Count', 'y': 'Source IP'},
                title="Top 10 Source IPs"
            )
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white')
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Top HTTP hosts
        if 'http_host' in df.columns:
            st.markdown("**Top HTTP Hosts**")
            http_hosts = df[df['http_host'].notna()]['http_host'].value_counts().head(10)
            if not http_hosts.empty:
                fig = px.bar(
                    x=http_hosts.values,
                    y=http_hosts.index,
                    orientation='h',
                    labels={'x': 'Count', 'y': 'HTTP Host'},
                    title="Top 10 HTTP Hosts"
                )
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white')
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No HTTP host data available")
    
    # TLS SNI analysis
    if 'tls_sni' in df.columns:
        st.markdown("**TLS SNI Analysis**")
        tls_data = df[df['tls_sni'].notna()]
        if not tls_data.empty:
            top_sni = tls_data['tls_sni'].value_counts().head(15)
            fig = px.bar(
                x=top_sni.index,
                y=top_sni.values,
                labels={'x': 'TLS SNI', 'y': 'Count'},
                title="Top 15 TLS SNI Values"
            )
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white'),
                xaxis_tickangle=-45
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No TLS SNI data available")
    
    # Protocol distribution
    if 'proto' in df.columns:
        st.markdown("**Protocol Distribution**")
        proto_counts = df['proto'].value_counts()
        fig = px.pie(
            values=proto_counts.values,
            names=proto_counts.index,
            title="Protocol Distribution"
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Data type breakdown
    st.markdown("**Data Type Breakdown**")
    data_types = {
        'HTTP Records': df['http_host'].notna().sum() if 'http_host' in df.columns else 0,
        'TLS Records': df['tls_sni'].notna().sum() if 'tls_sni' in df.columns else 0,
        'URL Records': df['url'].notna().sum() if 'url' in df.columns else 0,
        'TLS JA3': df['tls_ja3'].notna().sum() if 'tls_ja3' in df.columns else 0
    }
    
    fig = px.bar(
        x=list(data_types.keys()),
        y=list(data_types.values()),
        labels={'x': 'Data Type', 'y': 'Count'},
        title="Metadata Type Distribution"
    )
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    st.plotly_chart(fig, use_container_width=True)

