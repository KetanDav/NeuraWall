"""
FL Charts Component
Federated Learning visualization and metrics
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

def render_fl_progress(rounds=5):
    """Render FL convergence progress"""
    
    accuracy_data = [95.2, 97.1, 98.3, 99.0, 99.5]
    f1_scores = [0.94, 0.96, 0.97, 0.985, 0.995]
    auc_scores = [0.955, 0.970, 0.985, 0.992, 0.998]
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=list(range(1, rounds + 1)),
        y=accuracy_data,
        mode='lines+markers',
        name='Accuracy',
        line=dict(color='#00a651', width=3),
        marker=dict(size=10)
    ))
    
    fig.add_trace(go.Scatter(
        x=list(range(1, rounds + 1)),
        y=[f * 100 for f in f1_scores],
        mode='lines+markers',
        name='F1-Score',
        line=dict(color='#0066cc', width=3),
        marker=dict(size=10)
    ))
    
    fig.add_trace(go.Scatter(
        x=list(range(1, rounds + 1)),
        y=[a * 100 for a in auc_scores],
        mode='lines+markers',
        name='AUC',
        line=dict(color='#ff9500', width=3),
        marker=dict(size=10)
    ))
    
    fig.update_layout(
        title="Federated Learning Convergence",
        xaxis_title="Round",
        yaxis_title="Score (%)",
        height=350,
        hovermode='x unified',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    
    return fig

def render_per_site_accuracy():
    """Render per-site accuracy comparison"""
    
    sites = ['Site A\n(Enterprise)', 'Site B\n(Cloud)', 'Site C\n(IoT)']
    before_fl = [98.44, 99.99, 99.62]
    after_fl = [99.12, 99.99, 99.75]
    
    fig = go.Figure(data=[
        go.Bar(name='Before FL', x=sites, y=before_fl, marker_color='#FFB6C1'),
        go.Bar(name='After FL', x=sites, y=after_fl, marker_color='#00a651')
    ])
    
    fig.update_layout(
        title="Per-Site Model Accuracy",
        yaxis_title="Accuracy (%)",
        height=350,
        barmode='group',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    
    return fig

def render_samples_aggregated():
    """Render samples aggregated per round"""
    
    rounds = ['Round 1', 'Round 2', 'Round 3', 'Round 4', 'Round 5']
    samples = [1976835, 1976835, 1976835, 1976835, 1976835]
    
    fig = go.Figure(data=[
        go.Bar(
            x=rounds,
            y=samples,
            marker_color='#0066cc',
            text=[f'{s/1e6:.2f}M' for s in samples],
            textposition='outside'
        )
    ])
    
    fig.update_layout(
        title="Samples Aggregated Per Round",
        yaxis_title="Sample Count",
        height=350,
        showlegend=False,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    
    return fig

def render_model_weights_distribution():
    """Render model weights distribution across sites"""
    
    sites = ['Site A', 'Site B', 'Site C']
    weights = [1.0, 1.5, 0.8]  # Different weights based on sample count
    
    fig = go.Figure(data=[
        go.Bar(
            x=sites,
            y=weights,
            marker_color=['#FF6B6B', '#4ECDC4', '#45B7D1']
        )
    ])
    
    fig.update_layout(
        title="Model Weight Distribution",
        yaxis_title="Weight Factor",
        height=350,
        showlegend=False,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    
    return fig
