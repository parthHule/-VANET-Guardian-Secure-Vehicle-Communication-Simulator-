#!/usr/bin/env python3

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import re
from typing import Dict, List, Tuple

class VanetAnalyzer:
    def __init__(self, trace_file: str):
        self.trace_file = Path(trace_file)
        self.data = self._load_trace_file()
        
    def _load_trace_file(self) -> pd.DataFrame:
        """Load and parse NS-3 trace file."""
        columns = ['event', 'time', 'node', 'x', 'y', 'z', 'packet_type', 'size', 'flags']
        data = []
        
        with open(self.trace_file) as f:
            for line in f:
                if line.startswith('t'):  # Transmission event
                    parts = line.strip().split()
                    data.append({
                        'event': parts[0],
                        'time': float(parts[1]),
                        'node': int(parts[2]),
                        'x': float(parts[3]),
                        'y': float(parts[4]),
                        'z': float(parts[5]),
                        'packet_type': parts[6],
                        'size': int(parts[7]),
                        'flags': parts[8] if len(parts) > 8 else ''
                    })
        
        return pd.DataFrame(data)
    
    def calculate_end_to_end_delay(self) -> Dict[str, float]:
        """Calculate average end-to-end delay for different packet types."""
        delays = {}
        
        # Group by packet type and calculate delays
        for packet_type in self.data['packet_type'].unique():
            packets = self.data[self.data['packet_type'] == packet_type]
            sent = packets[packets['event'] == 't']
            received = packets[packets['event'] == 'r']
            
            if not sent.empty and not received.empty:
                delay = (received['time'] - sent['time']).mean()
                delays[packet_type] = delay
        
        return delays
    
    def calculate_packet_delivery_ratio(self) -> Dict[str, float]:
        """Calculate packet delivery ratio for different packet types."""
        pdrs = {}
        
        for packet_type in self.data['packet_type'].unique():
            packets = self.data[self.data['packet_type'] == packet_type]
            sent = len(packets[packets['event'] == 't'])
            received = len(packets[packets['event'] == 'r'])
            
            if sent > 0:
                pdrs[packet_type] = received / sent
            else:
                pdrs[packet_type] = 0.0
        
        return pdrs
    
    def calculate_overhead(self) -> Dict[str, int]:
        """Calculate communication overhead in bytes."""
        overhead = {}
        
        for packet_type in self.data['packet_type'].unique():
            packets = self.data[self.data['packet_type'] == packet_type]
            total_bytes = packets['size'].sum()
            overhead[packet_type] = total_bytes
        
        return overhead
    
    def analyze_attack_effectiveness(self) -> Dict[str, float]:
        """Analyze the effectiveness of different attacks."""
        attacks = {}
        
        # Analyze black hole attacks
        blackhole = self.data[self.data['flags'].str.contains('BLACKHOLE', na=False)]
        if not blackhole.empty:
            attacks['blackhole'] = len(blackhole[blackhole['event'] == 'r']) / len(blackhole)
        
        # Analyze Sybil attacks
        sybil = self.data[self.data['flags'].str.contains('SYBIL', na=False)]
        if not sybil.empty:
            attacks['sybil'] = len(sybil[sybil['event'] == 'r']) / len(sybil)
        
        # Analyze replay attacks
        replay = self.data[self.data['flags'].str.contains('REPLAY', na=False)]
        if not replay.empty:
            attacks['replay'] = len(replay[replay['event'] == 'r']) / len(replay)
        
        return attacks
    
    def plot_results(self, output_dir: str):
        """Generate plots for various metrics."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Plot end-to-end delay
        delays = self.calculate_end_to_end_delay()
        plt.figure(figsize=(10, 6))
        plt.bar(delays.keys(), delays.values())
        plt.title('Average End-to-End Delay by Packet Type')
        plt.xlabel('Packet Type')
        plt.ylabel('Delay (seconds)')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(output_dir / 'end_to_end_delay.png')
        plt.close()
        
        # Plot packet delivery ratio
        pdrs = self.calculate_packet_delivery_ratio()
        plt.figure(figsize=(10, 6))
        plt.bar(pdrs.keys(), pdrs.values())
        plt.title('Packet Delivery Ratio by Packet Type')
        plt.xlabel('Packet Type')
        plt.ylabel('PDR')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(output_dir / 'packet_delivery_ratio.png')
        plt.close()
        
        # Plot communication overhead
        overhead = self.calculate_overhead()
        plt.figure(figsize=(10, 6))
        plt.bar(overhead.keys(), overhead.values())
        plt.title('Communication Overhead by Packet Type')
        plt.xlabel('Packet Type')
        plt.ylabel('Total Bytes')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(output_dir / 'communication_overhead.png')
        plt.close()
        
        # Plot attack effectiveness
        attacks = self.analyze_attack_effectiveness()
        if attacks:
            plt.figure(figsize=(10, 6))
            plt.bar(attacks.keys(), attacks.values())
            plt.title('Attack Detection Effectiveness')
            plt.xlabel('Attack Type')
            plt.ylabel('Detection Rate')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(output_dir / 'attack_effectiveness.png')
            plt.close()
    
    def generate_report(self, output_file: str):
        """Generate a comprehensive analysis report."""
        delays = self.calculate_end_to_end_delay()
        pdrs = self.calculate_packet_delivery_ratio()
        overhead = self.calculate_overhead()
        attacks = self.analyze_attack_effectiveness()
        
        with open(output_file, 'w') as f:
            f.write("VANET Secure Routing Protocol Analysis Report\n")
            f.write("===========================================\n\n")
            
            f.write("1. End-to-End Delay\n")
            f.write("-----------------\n")
            for packet_type, delay in delays.items():
                f.write(f"{packet_type}: {delay:.3f} seconds\n")
            f.write("\n")
            
            f.write("2. Packet Delivery Ratio\n")
            f.write("----------------------\n")
            for packet_type, pdr in pdrs.items():
                f.write(f"{packet_type}: {pdr:.2%}\n")
            f.write("\n")
            
            f.write("3. Communication Overhead\n")
            f.write("------------------------\n")
            for packet_type, bytes_sent in overhead.items():
                f.write(f"{packet_type}: {bytes_sent:,} bytes\n")
            f.write("\n")
            
            if attacks:
                f.write("4. Attack Detection Effectiveness\n")
                f.write("-------------------------------\n")
                for attack_type, effectiveness in attacks.items():
                    f.write(f"{attack_type}: {effectiveness:.2%}\n")
                f.write("\n")
            
            f.write("5. Summary\n")
            f.write("---------\n")
            f.write(f"Average PDR across all packet types: {np.mean(list(pdrs.values())):.2%}\n")
            f.write(f"Average delay across all packet types: {np.mean(list(delays.values())):.3f} seconds\n")
            f.write(f"Total communication overhead: {sum(overhead.values()):,} bytes\n")
            if attacks:
                f.write(f"Average attack detection rate: {np.mean(list(attacks.values())):.2%}\n")

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Analyze VANET simulation results')
    parser.add_argument('trace_file', help='Path to NS-3 trace file')
    parser.add_argument('--output-dir', default='results', help='Output directory for plots')
    parser.add_argument('--report-file', default='results/report.txt', help='Output file for analysis report')
    args = parser.parse_args()
    
    analyzer = VanetAnalyzer(args.trace_file)
    analyzer.plot_results(args.output_dir)
    analyzer.generate_report(args.report_file)

if __name__ == '__main__':
    main() 