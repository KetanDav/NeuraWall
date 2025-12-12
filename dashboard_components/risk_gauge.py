"""
Risk Gauge Component
Displays risk score visualization with breakdown
"""

import streamlit as st
import plotly.graph_objects as go
import numpy as np

def render_risk_gauge(risk_score):
    """Render risk score gauge"""
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=risk_score * 100,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Overall Risk Score"},
        delta={'reference': 50},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 30], 'color': "#90EE90"},
                {'range': [30, 60], 'color': "#FFD700"},
                {'range': [60, 85], 'color': "#FF8C00"},
                {'range': [85, 100], 'color': "#FF0000"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    fig.update_layout(
        height=350,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    return fig

def render_risk_breakdown(ml_prob, anomaly_score, behavioral_score):
    """Render risk component breakdown"""
    
    # Calculate individual contributions
    ml_contribution = 0.6 * ml_prob * 100
    anomaly_contribution = 0.25 * anomaly_score * 100
    behavioral_contribution = 0.15 * behavioral_score * 100
    
    fig = go.Figure(data=[
        go.Bar(
            name='ML Probability (60%)',
            x=['Risk Components'],
            y=[ml_contribution],
            marker_color='#0066cc'
        ),
        go.Bar(
            name='Anomaly Detection (25%)',
            x=['Risk Components'],
            y=[anomaly_contribution],
            marker_color='#ff9500'
        ),
        go.Bar(
            name='Behavioral (15%)',
            x=['Risk Components'],
            y=[behavioral_contribution],
            marker_color='#d62728'
        )
    ])
    
    fig.update_layout(
        barmode='stack',
        title="Risk Score Breakdown",
        height=350,
        showlegend=True,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    return fig

def render_risk_levels(flows):
    """Render distribution of risk levels"""
    
    risk_levels = {'ALLOW': 0, 'ALERT': 0, 'BLOCK': 0, 'QUARANTINE': 0}
    
    for flow in flows:
        risk = 0.6 * flow['model_prob'] + 0.25 * flow['anomaly_score']
        
        if risk < 0.30:
            risk_levels['ALLOW'] += 1
        elif risk < 0.60:
            risk_levels['ALERT'] += 1
        elif risk < 0.85:
            risk_levels['BLOCK'] += 1
        else:
            risk_levels['QUARANTINE'] += 1
    
    fig = go.Figure(data=[
        go.Bar(
            x=list(risk_levels.keys()),
            y=list(risk_levels.values()),
            marker_color=['#90EE90', '#FFD700', '#FF8C00', '#FF0000']
        )
    ])
    
    fig.update_layout(
        title="Traffic Distribution by Risk Level",
        xaxis_title="Risk Level",
        yaxis_title="Flow Count",
        height=350,
        showlegend=False,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white')
    )
    return fig
