import streamlit as st
import time
from vanet_simulation import Vehicle, VehicleType, simulate, plot_speeds, plot_positions
import matplotlib.pyplot as plt
import io
import numpy as np

# Page configuration
st.set_page_config(
    page_title="VANET Secure Routing Simulation",
    page_icon="🚗",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
    <style>
    .main {
        padding: 1rem 2rem;
    }
    .title-container {
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        padding: 2.5rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        text-align: center;
        color: white;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .title-container h1 {
        color: white !important;
        font-size: 2.5em !important;
        font-weight: 700 !important;
        margin-bottom: 0.5rem !important;
    }
    .title-container p {
        color: rgba(255, 255, 255, 0.9) !important;
        font-size: 1.2em !important;
    }
    .feature-container {
        background-color: white;
        padding: 2rem;
        border-radius: 15px;
        border: 1px solid #e0e0e0;
        margin-bottom: 1.5rem;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
    }
    .feature-container h2 {
        color: #1e3c72;
        font-size: 1.8em;
        margin-bottom: 1rem;
        font-weight: 600;
    }
    .feature-container h3 {
        color: #2a5298;
        font-size: 1.3em;
        margin-bottom: 0.8rem;
    }
    .feature-container ul {
        list-style-type: none;
        padding-left: 0;
    }
    .feature-container ul li {
        padding: 0.5rem 0;
        color: #444;
        font-size: 1.1em;
    }
    .feature-container ul li:before {
        content: "→";
        color: #2a5298;
        font-weight: bold;
        margin-right: 0.5rem;
    }
    .metric-container {
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        padding: 1.5rem;
        border-radius: 15px;
        margin-bottom: 1.5rem;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
    }
    .metric-container h3 {
        color: #1e3c72;
        font-size: 1.2em;
        margin-bottom: 0.5rem;
    }
    .stButton>button {
        width: 100%;
        background: linear-gradient(135deg, #2a5298 0%, #1e3c72 100%);
        color: white;
        padding: 0.8rem 1.5rem;
        font-size: 1.2em;
        font-weight: 600;
        border: none;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        transform: translateY(-2px);
    }
    [data-testid="stMetricValue"] {
        font-size: 1.8em !important;
        color: #1e3c72 !important;
        font-weight: 600 !important;
    }
    [data-testid="stMetricLabel"] {
        font-size: 1em !important;
        color: #666 !important;
    }
    .stProgress > div > div > div {
        background-color: #2a5298;
    }
    .sidebar .sidebar-content {
        background-color: #f8f9fa;
    }
    </style>
""", unsafe_allow_html=True)

# Title Section
st.markdown("""
    <div class="title-container">
        <h1>🚗 VANET Secure Routing Simulation</h1>
        <p>
            A Real-time Vehicular Ad-hoc Network Simulation with Advanced Security Features
        </p>
    </div>
""", unsafe_allow_html=True)

# Introduction
st.markdown("""
    <div class="feature-container">
        <h2>🎯 Project Overview</h2>
        <p style='font-size: 1.2em; color: #444; line-height: 1.6;'>
            This simulation demonstrates a state-of-the-art approach to secure vehicular communication in smart cities. 
            Using advanced cryptographic techniques and trust mechanisms, we simulate how vehicles can safely exchange 
            information while protecting against various cyber threats.
        </p>
    </div>
""", unsafe_allow_html=True)

# Key Features Section
st.markdown("""
    <div class="feature-container">
        <h2>✨ Key Features</h2>
        <div style='display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;'>
            <div>
                <h3>🔐 Security</h3>
                <ul>
                    <li>HMAC Authentication</li>
                    <li>Trust Scoring System</li>
                    <li>Attack Detection</li>
                </ul>
            </div>
            <div>
                <h3>🚦 Vehicle Types</h3>
                <ul>
                    <li>Emergency Vehicles</li>
                    <li>Public Transport</li>
                    <li>Regular Vehicles</li>
                </ul>
            </div>
            <div>
                <h3>📊 Real-time Metrics</h3>
                <ul>
                    <li>Packet Delivery Ratio</li>
                    <li>Attack Detection Rate</li>
                    <li>Trust Scores</li>
                </ul>
            </div>
            <div>
                <h3>🛡️ Safety Features</h3>
                <ul>
                    <li>Collision Detection</li>
                    <li>Route Optimization</li>
                    <li>Speed Management</li>
                </ul>
            </div>
        </div>
    </div>
""", unsafe_allow_html=True)

# Sidebar Configuration
st.sidebar.markdown("""
    <div style='text-align: center; padding: 1rem;'>
        <h2>⚙️ Simulation Controls</h2>
    </div>
""", unsafe_allow_html=True)

st.sidebar.markdown("---")
st.sidebar.header("Vehicle Parameters")
num_vehicles = st.sidebar.slider("🚗 Number of Vehicles", 2, 10, 4)
num_steps = st.sidebar.slider("⏱️ Simulation Steps", 20, 200, 50)
dt = st.sidebar.number_input("🕐 Time Step (dt)", 0.1, 1.0, 0.1)

st.sidebar.markdown("---")
st.sidebar.header("Vehicle Distribution")
emergency_pct = st.sidebar.slider("🚑 Emergency Vehicles %", 0, 100, 25)
public_transport_pct = st.sidebar.slider("🚌 Public Transport %", 0, 100, 25)

# Initialize metrics placeholders
if 'metrics' not in st.session_state:
    st.session_state.metrics = {
        'pdr': 0.0,
        'messages': 0,
        'attack_rate': 0.0,
        'trust_score': 0.0
    }

# Metrics Display Section
st.markdown("<div class='metric-container'>", unsafe_allow_html=True)
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown("### 📡 PDR")
    pdr_metric = st.metric("Packet Delivery Ratio", f"{st.session_state.metrics['pdr']:.2%}")
with col2:
    st.markdown("### 📨 Messages")
    msg_metric = st.metric("Messages Received", st.session_state.metrics['messages'])
with col3:
    st.markdown("### 🛡️ Security")
    attack_metric = st.metric("Attack Detection Rate", f"{st.session_state.metrics['attack_rate']:.2%}")
with col4:
    st.markdown("### ⭐ Trust")
    trust_metric = st.metric("Average Trust Score", f"{st.session_state.metrics['trust_score']:.2f}")
st.markdown("</div>", unsafe_allow_html=True)

# Simulation Control
st.markdown("""
    <div class='feature-container'>
        <h2>▶️ Simulation Control</h2>
    </div>
""", unsafe_allow_html=True)
start_button = st.button("Start Simulation")

# Rest of your existing simulation code
if start_button:
    # Create progress bar
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Create vehicles based on distribution
    vehicles = []
    for i in range(num_vehicles):
        rand_val = np.random.random() * 100
        if rand_val < emergency_pct:
            v_type = VehicleType.EMERGENCY
        elif rand_val < emergency_pct + public_transport_pct:
            v_type = VehicleType.PUBLIC_TRANSPORT
        else:
            v_type = VehicleType.REGULAR
            
        vehicles.append(Vehicle(
            f"V{i+1}",
            speed=np.random.uniform(30, 80),
            position=(np.random.uniform(0, 100), np.random.uniform(0, 100)),
            vehicle_type=v_type
        ))
    
    # Create placeholder for plots
    plot_container = st.empty()
    
    # Run simulation
    for step in range(num_steps):
        # Update progress
        progress = (step + 1) / num_steps
        progress_bar.progress(progress)
        status_text.text(f"Running simulation... Step {step + 1}/{num_steps}")
        
        # Run one step of simulation
        metrics = simulate(vehicles, dt, 1)
        current_metrics = metrics[0]
        
        # Update metrics
        st.session_state.metrics['pdr'] = current_metrics['pdr']
        st.session_state.metrics['messages'] = current_metrics['valid_messages']
        st.session_state.metrics['attack_rate'] = current_metrics['attack_detection_rate']
        st.session_state.metrics['trust_score'] = current_metrics['avg_trust']
        
        # Update metrics display
        col1.metric("Packet Delivery Ratio", f"{current_metrics['pdr']:.2%}")
        col2.metric("Messages Received", current_metrics['valid_messages'])
        col3.metric("Attack Detection Rate", f"{current_metrics['attack_detection_rate']:.2%}")
        col4.metric("Average Trust Score", f"{current_metrics['avg_trust']:.2f}")
        
        # Create and update plots
        fig = plt.figure(figsize=(15, 10))
        
        # Speed plot
        plt.subplot(2, 1, 1)
        for vehicle in vehicles:
            color = {
                VehicleType.EMERGENCY: 'red',
                VehicleType.PUBLIC_TRANSPORT: 'green',
                VehicleType.REGULAR: 'blue'
            }[vehicle.vehicle_type]
            plt.plot([step], [vehicle.speed], 'o', color=color, 
                    label=f"{vehicle.id} ({vehicle.vehicle_type.value})")
        plt.title("Vehicle Speeds")
        plt.xlabel("Time Step")
        plt.ylabel("Speed (m/s)")
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.grid(True, alpha=0.3)
        
        # Position plot
        plt.subplot(2, 1, 2)
        for vehicle in vehicles:
            color = {
                VehicleType.EMERGENCY: 'red',
                VehicleType.PUBLIC_TRANSPORT: 'green',
                VehicleType.REGULAR: 'blue'
            }[vehicle.vehicle_type]
            plt.plot(vehicle.position[0], vehicle.position[1], 'o', color=color,
                    label=f"{vehicle.id} ({vehicle.vehicle_type.value})")
        plt.title("Vehicle Positions")
        plt.xlabel("X Position")
        plt.ylabel("Y Position")
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.grid(True, alpha=0.3)
        plt.axis('equal')
        
        plt.tight_layout()
        
        # Convert plot to image and display
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        buf.seek(0)
        plot_container.image(buf)
        plt.close()
        
        # Small delay to make visualization smoother
        time.sleep(0.1)
    
    status_text.text("Simulation completed!")

# Footer with enhanced styling
st.markdown("""
    <div style='margin-top: 3rem; text-align: center; padding: 2rem; background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); border-radius: 15px; color: white;'>
        <p style='font-size: 1.2em; margin-bottom: 0.5rem;'>Developed as part of Advanced VANET Security Research</p>
        <p style='font-size: 0.9em; opacity: 0.9;'>© 2024 All rights reserved</p>
    </div>
""", unsafe_allow_html=True) 