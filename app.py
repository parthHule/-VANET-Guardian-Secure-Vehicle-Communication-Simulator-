import streamlit as st
import sys
import os
import json
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np

# Add the project root directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.simulation.vanet_sim import VANETSimulation, SimulationConfig

# Set matplotlib style
plt.style.use('dark_background')

def create_comparative_analysis_section(simulation):
    """Create the comparative analysis section in the Streamlit app"""
    st.header("📊 Comparative Analysis")
    
    # Generate comparison report
    report = json.loads(simulation.generate_comparative_report('json'))
    
    # Display overall scores
    st.subheader("Overall System Scores")
    scores_df = pd.DataFrame({
        'System': list(report['overall_scores'].keys()),
        'Score': list(report['overall_scores'].values())
    })
    
    fig = px.bar(scores_df, x='System', y='Score', 
                 title='Overall System Scores',
                 color='Score',
                 color_continuous_scale='Viridis',
                 template='plotly_dark')
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff')
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Display detailed metrics
    st.subheader("Detailed System Metrics")
    metrics_df = pd.DataFrame(report['systems']).T
    metrics_df.index.name = 'System'
    st.dataframe(metrics_df.style.background_gradient(cmap='viridis', axis=None))
    
    # Display comparative advantages
    st.subheader("VANET Guardian Advantages")
    for advantage in report['comparative_analysis']['VANET Guardian']:
        st.success(advantage)
    
    # Display radar chart for main metrics
    st.subheader("Main Metrics Comparison")
    main_metrics = ['security', 'performance', 'visualization', 'features', 'ux']
    radar_data = []
    
    for system in report['systems']:
        values = [report['systems'][system][metric] for metric in main_metrics]
        radar_data.append({
            'System': system,
            'Metric': main_metrics,
            'Value': values
        })
    
    radar_df = pd.DataFrame(radar_data)
    radar_df = radar_df.explode(['Metric', 'Value'])
    
    fig = px.line_polar(radar_df, r='Value', theta='Metric', 
                       line_close=True, color='System',
                       title='Main Metrics Radar Chart',
                       template='plotly_dark')
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff')
    )
    st.plotly_chart(fig, use_container_width=True)

def create_simulation_section():
    """Create the simulation section in the Streamlit app"""
    st.header("🚗 VANET Guardian Simulation")
    
    # Simulation parameters
    st.subheader("Simulation Parameters")
    col1, col2 = st.columns(2)
    
    with col1:
        num_vehicles = st.slider("Number of Vehicles", 10, 100, 50)
        num_malicious = st.slider("Number of Malicious Vehicles", 0, 20, 5)
        sim_time = st.slider("Simulation Time (seconds)", 60, 600, 300)
    
    with col2:
        area_size = st.slider("Area Size (meters)", 500, 2000, 1000)
        min_speed = st.slider("Minimum Speed (km/h)", 10, 40, 20)
        max_speed = st.slider("Maximum Speed (km/h)", 30, 80, 50)
    
    beacon_interval = st.slider("Beacon Interval (seconds)", 0.5, 5.0, 1.0, 0.5)
    communication_range = st.slider("Communication Range (meters)", 100, 500, 200)
    
    # Run simulation button
    if st.button("Run Simulation"):
        with st.spinner("Running simulation..."):
            # Initialize simulation
            config = SimulationConfig(
                num_vehicles=num_vehicles,
                num_malicious=num_malicious,
                sim_time=sim_time,
                area_size=area_size,
                min_speed=min_speed,
                max_speed=max_speed,
                beacon_interval=beacon_interval,
                communication_range=communication_range
            )
            
            simulation = VANETSimulation(config)
            simulation.run()
            
            # Display simulation results
            st.subheader("Simulation Results")
            
            # Create tabs for different visualizations
            tab1, tab2, tab3 = st.tabs(["Performance Metrics", "Vehicle Movement", "Comparative Analysis"])
            
            with tab1:
                # Performance metrics plots
                fig, axes = plt.subplots(2, 2, figsize=(15, 12))
                
                # Set colors for plots
                colors = ['#00ff00', '#00ffff', '#ff0000', '#ffff00']
                
                # Packet Delivery Ratio
                axes[0, 0].plot(np.linspace(0, config.sim_time, len(simulation.stats['packet_delivery_ratio'])),
                              simulation.stats['packet_delivery_ratio'], color=colors[0])
                axes[0, 0].set_title('Packet Delivery Ratio', color='#ffffff')
                axes[0, 0].set_xlabel('Time (s)', color='#ffffff')
                axes[0, 0].set_ylabel('PDR', color='#ffffff')
                
                # Message Statistics
                axes[0, 1].plot(np.linspace(0, config.sim_time, len(simulation.stats['messages_sent'])),
                              simulation.stats['messages_sent'], label='Sent', color=colors[1])
                axes[0, 1].plot(np.linspace(0, config.sim_time, len(simulation.stats['messages_received'])),
                              simulation.stats['messages_received'], label='Received', color=colors[2])
                axes[0, 1].set_title('Message Statistics', color='#ffffff')
                axes[0, 1].set_xlabel('Time (s)', color='#ffffff')
                axes[0, 1].set_ylabel('Number of Messages', color='#ffffff')
                axes[0, 1].legend()
                
                # Attack Statistics
                axes[1, 0].plot(np.linspace(0, config.sim_time, len(simulation.stats['attacks_attempted'])),
                              simulation.stats['attacks_attempted'], label='Attempted', color=colors[2])
                axes[1, 0].plot(np.linspace(0, config.sim_time, len(simulation.stats['attacks_detected'])),
                              simulation.stats['attacks_detected'], label='Detected', color=colors[3])
                axes[1, 0].set_title('Attack Statistics', color='#ffffff')
                axes[1, 0].set_xlabel('Time (s)', color='#ffffff')
                axes[1, 0].set_ylabel('Number of Attacks', color='#ffffff')
                axes[1, 0].legend()
                
                # Trust Scores
                axes[1, 1].plot(np.linspace(0, config.sim_time, len(simulation.stats['trust_scores'])),
                              simulation.stats['trust_scores'], color=colors[0])
                axes[1, 1].set_title('Average Trust Scores', color='#ffffff')
                axes[1, 1].set_xlabel('Time (s)', color='#ffffff')
                axes[1, 1].set_ylabel('Trust Score', color='#ffffff')
                
                # Set background color for all subplots
                for ax in axes.flat:
                    ax.set_facecolor('#000000')
                    ax.grid(True, linestyle='--', alpha=0.3)
                
                plt.tight_layout()
                st.pyplot(fig)
            
            with tab2:
                # Vehicle movement visualization
                st.subheader("Vehicle Movement")
                # Create a scatter plot of vehicle positions
                positions = []
                for vehicle in simulation.vehicles.values():
                    positions.append({
                        'Vehicle ID': vehicle.id,
                        'X': vehicle.position.x,
                        'Y': vehicle.position.y,
                        'Type': 'Malicious' if vehicle.is_malicious else 'Normal'
                    })
                
                positions_df = pd.DataFrame(positions)
                fig = px.scatter(positions_df, x='X', y='Y', 
                               color='Type', hover_data=['Vehicle ID'],
                               title='Vehicle Positions',
                               template='plotly_dark',
                               color_discrete_map={'Normal': '#00ff00', 'Malicious': '#ff0000'})
                fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='#ffffff')
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with tab3:
                # Display comparative analysis
                create_comparative_analysis_section(simulation)

def main():
    st.set_page_config(
        page_title="VANET Guardian",
        page_icon="🚗",
        layout="wide"
    )
    
    # Custom CSS
    st.markdown("""
        <style>
        .stApp {
            background-color: #000000;
            color: #ffffff;
        }
        .stButton>button {
            background-color: #00ff00;
            color: #000000;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        .stButton>button:hover {
            background-color: #00cc00;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,255,0,0.2);
        }
        .stSlider>div>div>div {
            background-color: #00ff00;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 2px;
        }
        .stTabs [data-baseweb="tab"] {
            background-color: #1a1a1a;
            border-radius: 4px;
            padding: 10px 16px;
            color: #ffffff;
        }
        .stTabs [aria-selected="true"] {
            background-color: #00ff00;
            color: #000000;
        }
        .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
            color: #ffffff;
        }
        .stSuccess {
            background-color: #1a1a1a;
            border-color: #00ff00;
            color: #00ff00;
        }
        .feature-box {
            background-color: #1a1a1a;
            border-radius: 10px;
            padding: 20px;
            margin: 10px 0;
            border: 1px solid #00ff00;
        }
        .project-links {
            display: flex;
            gap: 20px;
            margin: 20px 0;
        }
        .project-link {
            background-color: #1a1a1a;
            padding: 15px 25px;
            border-radius: 8px;
            text-decoration: none;
            color: #00ff00;
            border: 1px solid #00ff00;
            transition: all 0.3s ease;
        }
        .project-link:hover {
            background-color: #00ff00;
            color: #000000;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Title and description
    st.title("🚗 VANET Guardian")
    st.markdown("""
        ### Secure Vehicle Communication Simulator
        A comprehensive platform for simulating and analyzing secure vehicle-to-vehicle communication in VANETs.
    """)
    
    # Project Links
    st.markdown("""
        <div class="project-links">
            <a href="https://github.com/parthHule/-VANET-Guardian-Secure-Vehicle-Communication-Simulator-" class="project-link">GitHub Repository</a>
            <a href="https://drive.google.com/drive/folders/1l7MZqFxpDW18HZCllAbMCUrZf5Z0HcSL" class="project-link">Project Drive</a>
        </div>
    """, unsafe_allow_html=True)
    
    # Key Features
    st.header("✨ Key Features")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
            <div class="feature-box">
                <h3>🔒 Security Features</h3>
                <ul>
                    <li>Advanced encryption protocols</li>
                    <li>Real-time attack detection</li>
                    <li>Secure message routing</li>
                    <li>Trust-based authentication</li>
                </ul>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
            <div class="feature-box">
                <h3>🚗 Vehicle Management</h3>
                <ul>
                    <li>Dynamic vehicle tracking</li>
                    <li>Real-time position monitoring</li>
                    <li>Speed and trajectory analysis</li>
                    <li>Vehicle behavior modeling</li>
                </ul>
            </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
            <div class="feature-box">
                <h3>📊 Real-time Metrics</h3>
                <ul>
                    <li>Performance monitoring</li>
                    <li>Security statistics</li>
                    <li>Network efficiency metrics</li>
                    <li>System health tracking</li>
                </ul>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
            <div class="feature-box">
                <h3>🎯 Target Users</h3>
                <ul>
                    <li>Researchers</li>
                    <li>Security analysts</li>
                    <li>Network engineers</li>
                    <li>Students</li>
                </ul>
            </div>
        """, unsafe_allow_html=True)
    
    # Technologies Used
    st.header("🛠️ Technologies Used")
    st.markdown("""
        <div class="feature-box">
            <ul>
                <li>Python 3.x</li>
                <li>Streamlit</li>
                <li>Matplotlib</li>
                <li>Plotly</li>
                <li>Pandas</li>
                <li>NumPy</li>
            </ul>
        </div>
    """, unsafe_allow_html=True)
    
    # Educational Value
    st.header("📚 Educational Value")
    st.markdown("""
        <div class="feature-box">
            <ul>
                <li>Hands-on VANET security experience</li>
                <li>Real-world attack simulation</li>
                <li>Network performance analysis</li>
                <li>Security protocol implementation</li>
            </ul>
        </div>
    """, unsafe_allow_html=True)
    
    # Create simulation section
    st.header("🚀 Start Simulation")
    create_simulation_section()

if __name__ == "__main__":
    main() 