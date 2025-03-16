import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import time
import os
from pathlib import Path
import sys
import io
import matplotlib.pyplot as plt

# Add the project root directory to Python path
project_root = str(Path(__file__).parent.parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)

from src.simulation.vanet_sim import VANETSimulation, SimulationConfig

# Custom styling
st.set_page_config(
    page_title="VANET Secure Routing Simulator",
    page_icon="🚗",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .main {
        background-color: #f5f7f9;
    }
    .stButton>button {
        background-color: #2e4057;
        color: white;
        border-radius: 5px;
        padding: 0.5rem 1rem;
        border: none;
        transition: all 0.3s;
    }
    .stButton>button:hover {
        background-color: #1a2634;
        transform: translateY(-2px);
    }
    .status-box {
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
        background-color: white;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .metric-card {
        background-color: white;
        padding: 1rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: bold;
        color: #2e4057;
    }
    .metric-label {
        color: #666;
        font-size: 0.9rem;
    }
    h1 {
        color: #2e4057;
        font-family: 'Helvetica Neue', sans-serif;
    }
    .stProgress > div > div > div > div {
        background-color: #2e4057;
    }
</style>
""", unsafe_allow_html=True)

def create_plotly_figure(simulation):
    """Create interactive plotly figures from simulation results."""
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=(
            'Packet Delivery Ratio',
            'Message Statistics',
            'Attack Statistics',
            'Average Trust Scores'
        )
    )
    
    time_range = pd.Series(range(len(simulation.stats['packet_delivery_ratio']))) * (
        simulation.config.sim_time / len(simulation.stats['packet_delivery_ratio']))
    
    # Plot 1: Packet Delivery Ratio
    fig.add_trace(
        go.Scatter(x=time_range, y=simulation.stats['packet_delivery_ratio'],
                  name='PDR', line=dict(color='#2e4057')),
        row=1, col=1
    )
    
    # Plot 2: Messages
    fig.add_trace(
        go.Scatter(x=time_range, y=simulation.stats['messages_sent'],
                  name='Messages Sent', line=dict(color='#2e4057')),
        row=1, col=2
    )
    fig.add_trace(
        go.Scatter(x=time_range, y=simulation.stats['messages_received'],
                  name='Messages Received', line=dict(color='#48a9a6')),
        row=1, col=2
    )
    
    # Plot 3: Attacks
    fig.add_trace(
        go.Scatter(x=time_range, y=simulation.stats['attacks_attempted'],
                  name='Attacks Attempted', line=dict(color='#e63946')),
        row=2, col=1
    )
    fig.add_trace(
        go.Scatter(x=time_range, y=simulation.stats['attacks_detected'],
                  name='Attacks Detected', line=dict(color='#2a9d8f')),
        row=2, col=1
    )
    
    # Plot 4: Trust Scores
    fig.add_trace(
        go.Scatter(x=time_range, y=simulation.stats['trust_scores'],
                  name='Trust Score', line=dict(color='#2e4057')),
        row=2, col=2
    )
    
    fig.update_layout(
        height=800,
        showlegend=True,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(t=60),
    )
    
    fig.update_xaxes(title_text="Time (s)", gridcolor='#eee')
    fig.update_yaxes(gridcolor='#eee')
    
    return fig

def generate_report(simulation):
    """Generate a report string from simulation results."""
    report = []
    report.append("VANET Secure Routing Simulation Report")
    report.append("=====================================")
    report.append(f"\nSimulation Configuration:")
    report.append(f"- Number of Vehicles: {simulation.config.num_vehicles}")
    report.append(f"- Number of Malicious Nodes: {simulation.config.num_malicious}")
    report.append(f"- Simulation Time: {simulation.config.sim_time} seconds")
    report.append(f"- Area Size: {simulation.config.area_size}x{simulation.config.area_size} meters")
    report.append(f"- Speed Range: {simulation.config.min_speed}-{simulation.config.max_speed} km/h")
    
    report.append("\nPerformance Metrics:")
    report.append(f"- Final Packet Delivery Ratio: {simulation.stats['packet_delivery_ratio'][-1]:.2%}")
    report.append(f"- Total Messages Sent: {simulation.stats['messages_sent'][-1]}")
    report.append(f"- Total Messages Received: {simulation.stats['messages_received'][-1]}")
    report.append(f"- Attacks Attempted: {simulation.stats['attacks_attempted'][-1]}")
    report.append(f"- Attacks Detected: {simulation.stats['attacks_detected'][-1]}")
    report.append(f"- Final Average Trust Score: {simulation.stats['trust_scores'][-1]:.2f}")
    
    return "\n".join(report)

def main():
    st.title("🚗 VANET Secure Routing Simulator")
    
    # Sidebar configuration
    st.sidebar.header("Simulation Parameters")
    
    num_vehicles = st.sidebar.slider("Number of Vehicles", 10, 200, 50)
    num_malicious = st.sidebar.slider("Number of Malicious Nodes", 0, num_vehicles//2, 5)
    sim_time = st.sidebar.slider("Simulation Time (s)", 60, 600, 300)
    area_size = st.sidebar.slider("Area Size (m)", 500, 2000, 1000)
    min_speed = st.sidebar.slider("Minimum Speed (km/h)", 0, 50, 20)
    max_speed = st.sidebar.slider("Maximum Speed (km/h)", min_speed, 100, 50)
    
    # Create columns for the metrics
    col1, col2, col3, col4 = st.columns(4)
    
    # Initialize session state
    if 'simulation_running' not in st.session_state:
        st.session_state.simulation_running = False
    if 'simulation_complete' not in st.session_state:
        st.session_state.simulation_complete = False
    
    # Start simulation button
    if not st.session_state.simulation_running and not st.session_state.simulation_complete:
        if st.button("Start Simulation"):
            st.session_state.simulation_running = True
            st.session_state.simulation_complete = False
            
            # Initialize simulation
            config = SimulationConfig(
                num_vehicles=num_vehicles,
                num_malicious=num_malicious,
                sim_time=sim_time,
                area_size=area_size,
                min_speed=min_speed,
                max_speed=max_speed
            )
            
            st.session_state.simulation = VANETSimulation(config)
            
            # Run simulation
            with st.spinner("Running simulation..."):
                st.session_state.simulation.run()
                
            st.session_state.simulation_running = False
            st.session_state.simulation_complete = True
            st.rerun()
    
    # Display results if simulation is complete
    if st.session_state.simulation_complete:
        sim = st.session_state.simulation
        
        # Display metrics
        with col1:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.markdown(f'<div class="metric-value">{sim.stats["packet_delivery_ratio"][-1]:.2%}</div>', unsafe_allow_html=True)
            st.markdown('<div class="metric-label">Packet Delivery Ratio</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
        with col2:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.markdown(f'<div class="metric-value">{sim.stats["messages_received"][-1]}</div>', unsafe_allow_html=True)
            st.markdown('<div class="metric-label">Messages Received</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
        with col3:
            detection_rate = sim.stats["attacks_detected"][-1]/max(1, sim.stats["attacks_attempted"][-1])
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.markdown(f'<div class="metric-value">{detection_rate:.2%}</div>', unsafe_allow_html=True)
            st.markdown('<div class="metric-label">Attack Detection Rate</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
        with col4:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.markdown(f'<div class="metric-value">{sim.stats["trust_scores"][-1]:.2f}</div>', unsafe_allow_html=True)
            st.markdown('<div class="metric-label">Average Trust Score</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Display interactive plots
        st.plotly_chart(create_plotly_figure(sim), use_container_width=True)
        
        # Generate report text
        report_text = generate_report(sim)
        
        # Display report in expandable section
        with st.expander("View Detailed Report"):
            st.text(report_text)
        
        # Save Results button
        if st.button("Save Results"):
            # Create results directory
            Path("results").mkdir(exist_ok=True)
            
            # Save report
            with open("results/simulation_report.txt", "w") as f:
                f.write(report_text)
            
            # Save plots
            sim.plot_results()
            
            # Create download buttons
            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    label="Download Report",
                    data=report_text,
                    file_name="simulation_report.txt",
                    mime="text/plain"
                )
            with col2:
                with open("results/simulation_results.png", "rb") as f:
                    st.download_button(
                        label="Download Plots",
                        data=f.read(),
                        file_name="simulation_results.png",
                        mime="image/png"
                    )
        
        # Reset button
        if st.button("Run New Simulation"):
            st.session_state.simulation_complete = False
            st.rerun()

if __name__ == "__main__":
    main() 