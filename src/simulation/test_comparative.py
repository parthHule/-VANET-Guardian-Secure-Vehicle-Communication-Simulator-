import sys
import os

# Add the project root directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.simulation.vanet_sim import VANETSimulation, SimulationConfig
import matplotlib.pyplot as plt
import json

def main():
    # Create results directory if it doesn't exist
    os.makedirs('results', exist_ok=True)
    
    # Initialize simulation configuration
    config = SimulationConfig(
        num_vehicles=50,
        num_malicious=5,
        sim_time=300.0,
        area_size=1000.0,
        min_speed=20.0,
        max_speed=50.0,
        beacon_interval=1.0,
        communication_range=200.0
    )
    
    # Create and run simulation
    print("Initializing VANET simulation...")
    simulation = VANETSimulation(config)
    
    print("Running simulation...")
    simulation.run()
    
    print("Generating simulation results...")
    simulation.plot_results()
    
    print("Generating comparative analysis...")
    # Generate comparison plots
    simulation.plot_comparison('results/comparison_plots.png')
    
    # Generate and save comparison report
    report = simulation.generate_comparative_report('json', 'results/comparison_report.json')
    print("\nComparative Analysis Report:")
    print(json.dumps(json.loads(report), indent=2))
    
    print("\nResults have been saved to the 'results' directory:")
    print("- Simulation results plot: results/simulation_results.png")
    print("- Comparison plots: results/comparison_plots.png")
    print("- Comparison report: results/comparison_report.json")

if __name__ == "__main__":
    main() 