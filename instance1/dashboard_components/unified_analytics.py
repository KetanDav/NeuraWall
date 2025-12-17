"""
Unified Analytics Component
Combines data from all three database tables for comprehensive analysis
"""

import streamlit as st
import pandas as pd
import sqlite3
from pathlib import Path
import plotly.express as px
import plotly.graph_objects as go

def get_unified_data(db_path='session.db', limit=1000):
    """
    Fetch and join data from all three tables
    
    Args:
        db_path: Path to SQLite database file
        limit: Maximum number of rows to fetch
    
    Returns:
        Dictionary with joined DataFrames
    """
    try:
        conn = sqlite3.connect(db_path)
        
        # Join all three tables on flow_key
        query = """
            SELECT 
                s.flow_key,
                s.ip_src,
                s.ip_dst,
                s.sport,
                s.dport,
                s.proto,
                s.decision_action,
                s.decision_label,
                s.decision_score,
                s.decision_tier,
                s.bytes_fwd,
                s.bytes_rev,
                s.pkt_count,
                s.dur,
                ff.state as flow_state,
                ff.sbytes,
                ff.dbytes,
                ff.Spkts,
                ff.Dpkts,
                ti.http_host,
                ti.http_path,
                ti.url,
                ti.tls_ja3,
                ti.tls_sni
            FROM sessions s
            LEFT JOIN flow_features ff ON s.flow_key = ff.flow_key
            LEFT JOIN ti_metadata ti ON s.flow_key = ti.flow_key
            ORDER BY s.last_ts DESC
            LIMIT ?
        """
        
        df = pd.read_sql_query(query, conn, params=(limit,))
        conn.close()
        
        return df
    
    except Exception as e:
        st.error(f"Error fetching unified data: {e}")
        return pd.DataFrame()

def render_unified_dashboard(db_path='session.db'):
    """Render unified dashboard combining all three tables"""
    
    st.subheader("Unified Network Security Dashboard")
    
    df = get_unified_data(db_path, limit=1000)
    
    if df.empty:
        st.info("No data available for unified analysis. Waiting for data...")
        return
    
    # Key Metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("Total Flows", len(df))
    
    with col2:
        if 'decision_action' in df.columns:
            blocked = len(df[df['decision_action'].str.contains('BLOCK|DENY|QUARANTINE', case=False, na=False)])
            st.metric("Blocked", blocked, f"{blocked/len(df)*100:.1f}%")
        else:
            st.metric("Blocked", "N/A")
    
    with col3:
        if 'decision_tier' in df.columns:
            critical = len(df[df['decision_tier'].str.contains('CRITICAL', case=False, na=False)])
            st.metric("Critical", critical)
        else:
            st.metric("Critical", "N/A")
    
    with col4:
        if 'http_host' in df.columns:
            http_flows = df['http_host'].notna().sum()
            st.metric("HTTP Flows", http_flows)
        else:
            st.metric("HTTP Flows", "N/A")
    
    with col5:
        if 'tls_sni' in df.columns:
            tls_flows = df['tls_sni'].notna().sum()
            st.metric("TLS Flows", tls_flows)
        else:
            st.metric("TLS Flows", "N/A")
    
    st.divider()
    
    # Decision Action Distribution
    if 'decision_action' in df.columns:
        st.markdown("### Decision Action Distribution")
        col1, col2 = st.columns(2)
        
        with col1:
            action_counts = df['decision_action'].value_counts()
            fig = px.pie(
                values=action_counts.values,
                names=action_counts.index,
                title="Decision Actions"
            )
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white')
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            tier_counts = df['decision_tier'].value_counts() if 'decision_tier' in df.columns else pd.Series()
            if not tier_counts.empty:
                fig = px.bar(
                    x=tier_counts.index,
                    y=tier_counts.values,
                    labels={'x': 'Risk Tier', 'y': 'Count'},
                    title="Risk Tier Distribution"
                )
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white')
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No tier data available")
    
    # Top Threat Indicators
    st.markdown("### Top Threat Indicators")
    col1, col2 = st.columns(2)
    
    with col1:
        # Top blocked source IPs
        if 'ip_src' in df.columns and 'decision_action' in df.columns:
            blocked_df = df[df['decision_action'].str.contains('BLOCK|DENY|QUARANTINE', case=False, na=False)]
            if not blocked_df.empty:
                top_blocked = blocked_df['ip_src'].value_counts().head(10)
                fig = px.bar(
                    x=top_blocked.values,
                    y=top_blocked.index,
                    orientation='h',
                    labels={'x': 'Block Count', 'y': 'Source IP'},
                    title="Top 10 Blocked Source IPs"
                )
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white')
                )
                st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Top suspicious HTTP hosts
        if 'http_host' in df.columns and 'decision_score' in df.columns:
            suspicious_df = df[(df['http_host'].notna()) & (df['decision_score'] > 0.7)]
            if not suspicious_df.empty:
                top_hosts = suspicious_df['http_host'].value_counts().head(10)
                fig = px.bar(
                    x=top_hosts.values,
                    y=top_hosts.index,
                    orientation='h',
                    labels={'x': 'Count', 'y': 'HTTP Host'},
                    title="Top 10 Suspicious HTTP Hosts"
                )
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white')
                )
                st.plotly_chart(fig, use_container_width=True)
    
    # Traffic Analysis
    if 'bytes_fwd' in df.columns and 'bytes_rev' in df.columns:
        st.markdown("### Traffic Volume Analysis")
        col1, col2 = st.columns(2)
        
        with col1:
            # Bytes forward vs reverse
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=df.index[:100],
                y=df['bytes_fwd'].head(100),
                mode='lines+markers',
                name='Bytes Forward',
                line=dict(color='#00a651')
            ))
            fig.add_trace(go.Scatter(
                x=df.index[:100],
                y=df['bytes_rev'].head(100),
                mode='lines+markers',
                name='Bytes Reverse',
                line=dict(color='#ff9500')
            ))
            fig.update_layout(
                title="Bytes Forward vs Reverse (Last 100 Flows)",
                xaxis_title="Flow Index",
                yaxis_title="Bytes",
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white')
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Packet count distribution
            if 'pkt_count' in df.columns:
                fig = px.histogram(
                    df,
                    x='pkt_count',
                    nbins=50,
                    title="Packet Count Distribution",
                    labels={'pkt_count': 'Packet Count', 'count': 'Frequency'}
                )
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white')
                )
                st.plotly_chart(fig, use_container_width=True)
    
    # Protocol and State Analysis
    if 'proto' in df.columns:
        st.markdown("### Protocol Analysis")
        col1, col2 = st.columns(2)
        
        with col1:
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
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            if 'flow_state' in df.columns:
                state_counts = df['flow_state'].value_counts().head(10)
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
                st.plotly_chart(fig, use_container_width=True)
    
    # Risk Score Analysis
    if 'decision_score' in df.columns:
        st.markdown("### Risk Score Distribution")
        fig = px.histogram(
            df,
            x='decision_score',
            nbins=50,
            title="Decision Score Distribution",
            labels={'decision_score': 'Risk Score', 'count': 'Frequency'},
            color_discrete_sequence=['#ff4444']
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        st.plotly_chart(fig, use_container_width=True)

