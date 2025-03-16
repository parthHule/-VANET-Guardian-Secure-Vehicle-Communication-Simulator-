#!/usr/bin/env python3

import argparse
from src.simulation.vanet_sim import VANETSimulation, SimulationConfig

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='VANET Secure Routing Simulation')
    parser.add_argument('--num-vehicles', type=int, default=50,
                      help='Number of vehicles in simulation')
    parser.add_argument('--num-malicious', type=int, default=5,
                      help='Number of malicious nodes')
    parser.add_argument('--sim-time', type=float, default=300.0,
                      help='Simulation time in seconds')
    parser.add_argument('--area-size', type=float, default=1000.0,
                      help='Simulation area size in meters')
    parser.add_argument('--min-speed', type=float, default=20.0,
                      help='Minimum vehicle speed in km/h')
    parser.add_argument('--max-speed', type=float, default=50.0,
                      help='Maximum vehicle speed in km/h')
    args = parser.parse_args()

    # Create simulation configuration
    config = SimulationConfig(
        num_vehicles=args.num_vehicles,
        num_malicious=args.num_malicious,
        sim_time=args.sim_time,
        area_size=args.area_size,
        min_speed=args.min_speed,
        max_speed=args.max_speed
    )

    # Create and run simulation
    print("Initializing simulation...")
    sim = VANETSimulation(config)
    
    print("Running simulation...")
    sim.run()
    
    print("Generating results...")
    sim.plot_results()
    sim.generate_report()
    
    print("Simulation completed successfully!")
    print("Results have been saved to the 'results' directory")

if __name__ == '__main__':
    main() 