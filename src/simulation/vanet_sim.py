import random
import time
import math
from typing import List, Dict, Set
from ..routing.secure_routing import SecureRoutingProtocol, Position, VehicleInfo, RouteEntry
import matplotlib.pyplot as plt
import numpy as np
from dataclasses import dataclass

@dataclass
class SimulationConfig:
    num_vehicles: int = 50
    num_malicious: int = 5
    sim_time: float = 300.0  # seconds
    area_size: float = 1000.0  # meters
    min_speed: float = 20.0  # km/h
    max_speed: float = 50.0  # km/h
    beacon_interval: float = 1.0  # seconds
    communication_range: float = 200.0  # meters

class VehicleNode:
    def __init__(self, vehicle_id: str, is_malicious: bool, config: SimulationConfig):
        self.id = vehicle_id
        self.is_malicious = is_malicious
        self.config = config
        
        # Initialize position and movement
        self.position = Position(
            x=random.uniform(0, config.area_size),
            y=random.uniform(0, config.area_size),
            z=0.0,
            timestamp=time.time()
        )
        self.speed = random.uniform(config.min_speed / 3.6, config.max_speed / 3.6)  # Convert to m/s
        self.direction = random.uniform(0, 2 * math.pi)
        
        # Initialize routing protocol
        self.router = SecureRoutingProtocol(vehicle_id)
        info = VehicleInfo(
            id=vehicle_id,
            position=self.position,
            speed=self.speed * 3.6,  # Convert to km/h
            direction=self.direction,
            trust_score=1.0
        )
        self.router.initialize_vehicle(info)
        
        # Statistics
        self.messages_sent = 0
        self.messages_received = 0
        self.attacks_attempted = 0
        self.attacks_detected = 0

    def update(self, dt: float):
        """Update vehicle position and state."""
        # Update position
        new_x = self.position.x + self.speed * math.cos(self.direction) * dt
        new_y = self.position.y + self.speed * math.sin(self.direction) * dt
        
        # Wrap around boundaries
        new_x = new_x % self.config.area_size
        new_y = new_y % self.config.area_size
        
        # Create new position
        new_pos = Position(
            x=new_x,
            y=new_y,
            z=0.0,
            timestamp=time.time()
        )
        
        # Update router with new position
        self.router.update_position(new_pos)
        self.position = new_pos
        
        # Randomly change direction
        if random.random() < 0.1:  # 10% chance to change direction
            self.direction = random.uniform(0, 2 * math.pi)

    def send_beacon(self):
        """Send periodic beacon message."""
        if not self.is_malicious:
            try:
                # Create beacon message with vehicle info
                info = VehicleInfo(
                    id=self.id,
                    position=self.position,
                    speed=self.speed * 3.6,  # Convert to km/h
                    direction=self.direction,
                    trust_score=1.0
                )
                message = f"{info.id}:{info.position.x}:{info.position.y}:{info.speed}:{info.direction}".encode()
                self.router.send_beacon()
                self.messages_sent += 1
            except Exception as e:
                print(f"Error sending beacon from {self.id}: {e}")
        else:
            # Malicious node might send false position
            self.attacks_attempted += 1
            try:
                false_pos = Position(
                    x=random.uniform(0, self.config.area_size),
                    y=random.uniform(0, self.config.area_size),
                    z=0.0,
                    timestamp=time.time()
                )
                info = VehicleInfo(
                    id=self.id,
                    position=false_pos,
                    speed=self.speed * 3.6,
                    direction=self.direction,
                    trust_score=1.0
                )
                message = f"{info.id}:{false_pos.x}:{false_pos.y}:{info.speed}:{info.direction}".encode()
                self.router.send_beacon()
            except Exception as e:
                print(f"Error sending malicious beacon from {self.id}: {e}")

    def receive_message(self, message: bytes, sender_id: str) -> bool:
        """Process received message."""
        if self.is_malicious:
            # Malicious node might drop messages
            self.attacks_attempted += 1
            if random.random() < 0.5:  # 50% chance to drop message
                return False
        
        try:
            success = self.router.receive_message(message)
            if success:
                self.messages_received += 1
            return success
        except Exception as e:
            print(f"Error receiving message at {self.id} from {sender_id}: {e}")
            return False

class VANETSimulation:
    def __init__(self, config: SimulationConfig):
        self.config = config
        self.vehicles: Dict[str, VehicleNode] = {}
        self.malicious_ids: Set[str] = set()
        self.time = 0.0
        self.stats = {
            'messages_sent': [],
            'messages_received': [],
            'attacks_attempted': [],
            'attacks_detected': [],
            'packet_delivery_ratio': [],
            'trust_scores': []
        }
        
        self._initialize_vehicles()

    def _initialize_vehicles(self):
        """Initialize vehicles in the simulation."""
        # Create malicious node IDs
        malicious_ids = set(random.sample(range(self.config.num_vehicles), self.config.num_malicious))
        
        # Create vehicles
        for i in range(self.config.num_vehicles):
            vehicle_id = f"vehicle_{i}"
            is_malicious = i in malicious_ids
            if is_malicious:
                self.malicious_ids.add(vehicle_id)
            
            self.vehicles[vehicle_id] = VehicleNode(vehicle_id, is_malicious, self.config)

    def run(self):
        """Run the simulation."""
        dt = 0.1  # Time step (seconds)
        next_beacon_time = 0.0
        
        while self.time < self.config.sim_time:
            # Update vehicle positions
            for vehicle in self.vehicles.values():
                vehicle.update(dt)
            
            # Send beacons
            if self.time >= next_beacon_time:
                self._send_beacons()
                next_beacon_time = self.time + self.config.beacon_interval
            
            # Simulate communication
            self._simulate_communication()
            
            # Collect statistics
            self._collect_stats()
            
            self.time += dt

    def _send_beacons(self):
        """Have all vehicles send beacon messages."""
        for vehicle in self.vehicles.values():
            vehicle.send_beacon()

    def _simulate_communication(self):
        """Simulate message exchange between vehicles in range."""
        for v1_id, v1 in self.vehicles.items():
            for v2_id, v2 in self.vehicles.items():
                if v1_id != v2_id:
                    try:
                        # Check if vehicles are in range
                        distance = math.sqrt(
                            (v1.position.x - v2.position.x) ** 2 +
                            (v1.position.y - v2.position.y) ** 2
                        )
                        if distance <= self.config.communication_range:
                            # Create and send test message
                            message = f"test_message_from_{v1_id}".encode()
                            v2.receive_message(message, v1_id)
                    except Exception as e:
                        print(f"Error in communication between {v1_id} and {v2_id}: {e}")

    def _collect_stats(self):
        """Collect simulation statistics."""
        total_sent = sum(v.messages_sent for v in self.vehicles.values())
        total_received = sum(v.messages_received for v in self.vehicles.values())
        total_attacks = sum(v.attacks_attempted for v in self.vehicles.values())
        total_detected = sum(v.attacks_detected for v in self.vehicles.values())
        
        self.stats['messages_sent'].append(total_sent)
        self.stats['messages_received'].append(total_received)
        self.stats['attacks_attempted'].append(total_attacks)
        self.stats['attacks_detected'].append(total_detected)
        
        if total_sent > 0:
            pdr = total_received / total_sent
        else:
            pdr = 0.0
        self.stats['packet_delivery_ratio'].append(pdr)
        
        # Calculate average trust scores
        trust_scores = []
        for v1 in self.vehicles.values():
            for v2_id in self.vehicles:
                if v1.id != v2_id:
                    trust_scores.append(v1.router.calculate_trust(v2_id))
        self.stats['trust_scores'].append(np.mean(trust_scores) if trust_scores else 0.0)

    def plot_results(self):
        """Plot simulation results."""
        plt.figure(figsize=(15, 10))
        
        # Plot 1: Packet Delivery Ratio
        plt.subplot(2, 2, 1)
        plt.plot(np.linspace(0, self.config.sim_time, len(self.stats['packet_delivery_ratio'])),
                self.stats['packet_delivery_ratio'])
        plt.title('Packet Delivery Ratio')
        plt.xlabel('Time (s)')
        plt.ylabel('PDR')
        
        # Plot 2: Messages Sent vs Received
        plt.subplot(2, 2, 2)
        plt.plot(np.linspace(0, self.config.sim_time, len(self.stats['messages_sent'])),
                self.stats['messages_sent'], label='Sent')
        plt.plot(np.linspace(0, self.config.sim_time, len(self.stats['messages_received'])),
                self.stats['messages_received'], label='Received')
        plt.title('Message Statistics')
        plt.xlabel('Time (s)')
        plt.ylabel('Number of Messages')
        plt.legend()
        
        # Plot 3: Attack Statistics
        plt.subplot(2, 2, 3)
        plt.plot(np.linspace(0, self.config.sim_time, len(self.stats['attacks_attempted'])),
                self.stats['attacks_attempted'], label='Attempted')
        plt.plot(np.linspace(0, self.config.sim_time, len(self.stats['attacks_detected'])),
                self.stats['attacks_detected'], label='Detected')
        plt.title('Attack Statistics')
        plt.xlabel('Time (s)')
        plt.ylabel('Number of Attacks')
        plt.legend()
        
        # Plot 4: Average Trust Scores
        plt.subplot(2, 2, 4)
        plt.plot(np.linspace(0, self.config.sim_time, len(self.stats['trust_scores'])),
                self.stats['trust_scores'])
        plt.title('Average Trust Scores')
        plt.xlabel('Time (s)')
        plt.ylabel('Trust Score')
        
        plt.tight_layout()
        plt.savefig('results/simulation_results.png')
        plt.close()

    def generate_report(self):
        """Generate a simulation report."""
        with open('results/simulation_report.txt', 'w') as f:
            f.write("VANET Secure Routing Simulation Report\n")
            f.write("====================================\n\n")
            
            f.write("Simulation Parameters:\n")
            f.write(f"Number of vehicles: {self.config.num_vehicles}\n")
            f.write(f"Number of malicious nodes: {self.config.num_malicious}\n")
            f.write(f"Simulation time: {self.config.sim_time} seconds\n")
            f.write(f"Area size: {self.config.area_size}x{self.config.area_size} meters\n")
            f.write(f"Speed range: {self.config.min_speed}-{self.config.max_speed} km/h\n\n")
            
            f.write("Final Statistics:\n")
            f.write(f"Total messages sent: {self.stats['messages_sent'][-1]}\n")
            f.write(f"Total messages received: {self.stats['messages_received'][-1]}\n")
            f.write(f"Final packet delivery ratio: {self.stats['packet_delivery_ratio'][-1]:.2%}\n")
            f.write(f"Total attacks attempted: {self.stats['attacks_attempted'][-1]}\n")
            f.write(f"Total attacks detected: {self.stats['attacks_detected'][-1]}\n")
            f.write(f"Attack detection rate: {self.stats['attacks_detected'][-1]/max(1, self.stats['attacks_attempted'][-1]):.2%}\n")
            f.write(f"Final average trust score: {self.stats['trust_scores'][-1]:.3f}\n") 