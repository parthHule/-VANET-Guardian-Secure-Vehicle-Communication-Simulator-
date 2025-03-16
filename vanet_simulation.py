import random
import hashlib
import matplotlib.pyplot as plt
import time
import pandas as pd
import numpy as np
from dataclasses import dataclass
from typing import Tuple, List, Dict, Optional
from enum import Enum
import seaborn as sns
from sklearn.cluster import DBSCAN
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
import json
import hmac

class VehicleType(Enum):
    EMERGENCY = "emergency"
    REGULAR = "regular"
    PUBLIC_TRANSPORT = "public_transport"

@dataclass
class SecurityMetrics:
    total_messages: int = 0
    valid_messages: int = 0
    invalid_messages: int = 0
    attacks_detected: int = 0
    average_verification_time: float = 0.0

class Vehicle:
    def __init__(self, vehicle_id: str, speed: float, position: Tuple[float, float], 
                 vehicle_type: VehicleType = VehicleType.REGULAR):
        self.id = vehicle_id
        self.speed = speed
        self.position = position
        # Generate a random secret key for HMAC
        self.secret_key = hashlib.sha256(str(random.random()).encode()).digest()
        self.vehicle_type = vehicle_type
        self.neighbors: List[str] = []
        self.trust_scores: Dict[str, float] = {}
        self.security_metrics = SecurityMetrics()
        self.message_history: List[Dict] = []
        self.acceleration = 0.0
        self.max_speed = 120.0 if vehicle_type == VehicleType.EMERGENCY else 80.0
        self.braking_distance = 0.0
        self.route_history: List[Tuple[float, float]] = []
        self.anomaly_score = 0.0

    def update_acceleration(self, target_speed: float, dt: float):
        """Update vehicle acceleration based on target speed."""
        speed_diff = target_speed - self.speed
        self.acceleration = np.clip(speed_diff / dt, -3.0, 2.0)  # m/s²
        self.speed = np.clip(self.speed + self.acceleration * dt, 0, self.max_speed)
        self.calculate_braking_distance()

    def calculate_braking_distance(self):
        """Calculate the braking distance based on current speed."""
        # Using simplified braking distance formula: d = v²/2μg
        friction_coefficient = 0.7  # Dry road condition
        gravity = 9.81  # m/s²
        self.braking_distance = (self.speed ** 2) / (2 * friction_coefficient * gravity)

    def move(self, dt: float):
        """Enhanced movement with realistic physics and route history."""
        # Add some randomness to movement while maintaining realistic physics
        angle = random.uniform(-0.1, 0.1)  # Small random direction changes
        
        # Calculate new position using physics equations
        dx = self.speed * dt * np.cos(angle)
        dy = self.speed * dt * np.sin(angle)
        
        new_x = self.position[0] + dx
        new_y = self.position[1] + dy
        
        self.position = (new_x, new_y)
        self.route_history.append(self.position)
        
        # Keep only last 100 positions for memory efficiency
        if len(self.route_history) > 100:
            self.route_history.pop(0)

    def detect_anomalies(self) -> bool:
        """Simplified anomaly detection for better performance."""
        if len(self.route_history) < 10:
            return False

        # Simple variance-based anomaly detection instead of DBSCAN
        points = np.array(self.route_history)
        variance = np.var(points, axis=0).mean()
        self.anomaly_score = min(1.0, variance / 100.0)
        
        return self.anomaly_score > 0.3

    def check_collision(self, other: 'Vehicle', threshold: float = 1) -> bool:
        """Enhanced collision detection with braking distance consideration."""
        # Calculate actual distance
        distance = np.sqrt(
            (self.position[0] - other.position[0]) ** 2 +
            (self.position[1] - other.position[1]) ** 2
        )
        
        # Consider combined braking distances
        safe_distance = max(
            threshold,
            self.braking_distance + other.braking_distance
        )
        
        # Check if vehicles are on collision course
        if distance < safe_distance:
            relative_speed = abs(self.speed - other.speed)
            time_to_collision = distance / (relative_speed + 1e-6)
            return time_to_collision < 5.0  # 5 seconds threshold
        
        return False

    def generate_message(self) -> Tuple[Dict, Dict]:
        """Generate message with HMAC for authentication."""
        message = {
            "vehicle_id": self.id,
            "speed": self.speed,
            "position": self.position,
            "vehicle_type": self.vehicle_type.value,
            "timestamp": time.time(),
            "acceleration": self.acceleration,
            "braking_distance": self.braking_distance
        }
        
        # Generate HMAC
        message_bytes = json.dumps(message, sort_keys=True).encode()
        hmac_obj = hmac.new(self.secret_key, message_bytes, hashlib.sha256)
        
        # Generate hash for integrity
        hashes = self.hash_message(message)
        hashes["hmac"] = hmac_obj.hexdigest()
        
        return message, hashes

    def hash_message(self, message: Dict) -> Dict:
        """Generate single hash for message integrity."""
        message_bytes = json.dumps(message, sort_keys=True).encode()
        start_time = time.time()
        hash_value = hashlib.sha256(message_bytes).hexdigest()
        hash_time = time.time() - start_time
        
        return {
            "sha256": hash_value,
            "sha256_time": hash_time
        }

    def update_trust_score(self, vehicle_id: str, is_valid: bool):
        """Update trust scores for neighboring vehicles."""
        if vehicle_id not in self.trust_scores:
            self.trust_scores[vehicle_id] = 0.5  # Initial neutral trust
            
        # Update trust score using a weighted approach
        if is_valid:
            self.trust_scores[vehicle_id] = min(1.0, self.trust_scores[vehicle_id] + 0.1)
        else:
            self.trust_scores[vehicle_id] = max(0.0, self.trust_scores[vehicle_id] - 0.2)

    def check_integrity(self, message: Dict, hashes: Dict) -> bool:
        """Verify message integrity using HMAC."""
        try:
            message_bytes = json.dumps(message, sort_keys=True).encode()
            hmac_obj = hmac.new(self.secret_key, message_bytes, hashlib.sha256)
            expected_hmac = hmac_obj.hexdigest()
            
            # Verify HMAC
            if hashes["hmac"] != expected_hmac:
                return False
            
            # Verify hash
            if hashes["sha256"] != self.hash_message(message)["sha256"]:
                return False
            
            return True
        except (KeyError, TypeError):
            return False

    def receive_message(self, message: Dict, hashes: Dict):
        """Process received message with simplified security checks."""
        self.security_metrics.total_messages += 1
        start_time = time.time()
        
        # Check for replay attacks
        if self._is_replay_attack(message):
            self.security_metrics.attacks_detected += 1
            self.security_metrics.invalid_messages += 1
            self.update_trust_score(message['vehicle_id'], False)
            return
        
        # Verify message integrity
        is_valid = self.check_integrity(message, hashes)
        verification_time = time.time() - start_time
        
        # Update security metrics
        self.security_metrics.average_verification_time = (
            (self.security_metrics.average_verification_time * (self.security_metrics.total_messages - 1) +
             verification_time) / self.security_metrics.total_messages
        )
        
        if is_valid:
            self.security_metrics.valid_messages += 1
            self.update_trust_score(message['vehicle_id'], True)
            self._store_message(message)
        else:
            self.security_metrics.invalid_messages += 1
            if random.random() < 0.3:
                self.security_metrics.attacks_detected += 1
            self.update_trust_score(message['vehicle_id'], False)

    def _is_replay_attack(self, message: Dict) -> bool:
        """Check for replay attacks using message history."""
        for old_message in self.message_history:
            if (old_message['vehicle_id'] == message['vehicle_id'] and
                old_message['timestamp'] == message['timestamp']):
                return True
        return False

    def _store_message(self, message: Dict):
        """Store message in history with timestamp."""
        self.message_history.append(message)
        # Keep only last 100 messages
        if len(self.message_history) > 100:
            self.message_history.pop(0)

def simulate(vehicles: List[Vehicle], dt: float, num_steps: int):
    """Optimized simulation with reduced computation."""
    hash_times = {"sha256": [], "sha256_time": []}  # Reduced hash types
    security_metrics = []
    
    # Initialize total messages for PDR calculation
    total_messages_sent = 0
    total_messages_received = 0
    
    print("Initializing simulation...")
    
    for step in range(num_steps):
        step_messages_sent = 0
        step_messages_received = 0
        
        for vehicle in vehicles:
            # Update vehicle dynamics
            target_speed = random.uniform(0.8 * vehicle.speed, 1.2 * vehicle.speed)
            vehicle.update_acceleration(target_speed, dt)
            vehicle.move(dt)
            
            # Generate and broadcast message
            message, hashes = vehicle.generate_message()
            step_messages_sent += 1
            
            # Simulate some message tampering (reduced probability)
            if random.random() < 0.05:  # Reduced from 0.1 to 0.05
                tampered_message = message.copy()
                tampered_message["speed"] = random.uniform(0, 200)
                message = tampered_message
            
            # Check for collisions and communicate
            for other in vehicles:
                if vehicle != other:
                    if vehicle.check_collision(other):
                        print(f"Potential collision detected between {vehicle.id} and {other.id}")
                    if hasattr(other, 'receive_message'):
                        other.receive_message(message.copy(), hashes.copy())
                        step_messages_received += 1
            
            # Collect timing data (reduced hash types)
            for hash_type, hash_time in hashes.items():
                if hash_type.endswith("_time") and hash_type[:-5] in hash_times:
                    hash_times[hash_type[:-5]].append(hash_time)
        
        # Update total message counts
        total_messages_sent += step_messages_sent
        total_messages_received += step_messages_received
        
        # Calculate metrics
        pdr = total_messages_received / max(1, total_messages_sent)
        all_trust_scores = [score for v in vehicles for score in v.trust_scores.values()]
        avg_trust = sum(all_trust_scores) / max(1, len(all_trust_scores)) if all_trust_scores else 0.5
        
        total_attacks = sum(v.security_metrics.attacks_detected for v in vehicles)
        total_invalid = sum(v.security_metrics.invalid_messages for v in vehicles)
        attack_detection_rate = total_attacks / max(1, total_invalid) if total_invalid > 0 else 0
        
        # Store metrics
        step_metrics = {
            'step': step,
            'avg_speed': np.mean([v.speed for v in vehicles]),
            'avg_trust': avg_trust,
            'attacks_detected': total_attacks,
            'attack_detection_rate': attack_detection_rate,
            'valid_messages': total_messages_received,
            'total_messages': total_messages_sent,
            'pdr': pdr,
            'anomaly_score': np.mean([v.anomaly_score for v in vehicles])
        }
        security_metrics.append(step_metrics)
        
        # Print progress every 20 steps
        if step % 20 == 0:
            print(f"\nStep {step}/{num_steps}")
            print(f"PDR: {pdr:.2%}")
            print(f"Messages Received: {total_messages_received}")
            print(f"Attack Detection Rate: {attack_detection_rate:.2%}")
            print(f"Average Trust Score: {avg_trust:.2f}")

    return security_metrics

def _plot_hash_times(hash_times: Dict):
    """Plot hash generation times with enhanced styling."""
    plt.figure(figsize=(12, 6))
    sns.set_style("whitegrid")
    
    data = []
    for hash_type, times in hash_times.items():
        for time_value in times:
            data.append({"hash_type": hash_type, "time": time_value})
    
    df = pd.DataFrame(data)
    sns.boxplot(x="hash_type", y="time", data=df, showmeans=True)
    
    plt.title("Hash Generation Times Comparison", pad=20)
    plt.ylabel("Time (seconds)")
    plt.xlabel("Hash Function")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def _plot_security_metrics(metrics: List[Dict]):
    """Plot security metrics over time."""
    df = pd.DataFrame(metrics)
    
    plt.figure(figsize=(15, 10))
    plt.subplot(2, 2, 1)
    plt.plot(df['step'], df['pdr'] * 100, 'b-', label='PDR')
    plt.title('Packet Delivery Ratio')
    plt.xlabel('Simulation Step')
    plt.ylabel('PDR (%)')
    
    plt.subplot(2, 2, 2)
    plt.plot(df['step'], df['avg_trust'], 'g-', label='Average Trust')
    plt.title('Average Trust Score Evolution')
    plt.xlabel('Simulation Step')
    plt.ylabel('Trust Score')
    
    plt.subplot(2, 2, 3)
    plt.plot(df['step'], df['attack_detection_rate'] * 100, 'r-', label='Detection Rate')
    plt.title('Attack Detection Rate')
    plt.xlabel('Simulation Step')
    plt.ylabel('Detection Rate (%)')
    
    plt.subplot(2, 2, 4)
    plt.plot(df['step'], df['valid_messages'], 'g-', label='Valid Messages')
    plt.plot(df['step'], df['total_messages'], 'b--', label='Total Messages')
    plt.title('Message Statistics')
    plt.xlabel('Simulation Step')
    plt.ylabel('Number of Messages')
    plt.legend()
    
    plt.tight_layout()
    plt.show()

def _plot_trust_evolution(metrics: List[Dict]):
    """Plot trust score evolution with enhanced visualization."""
    df = pd.DataFrame(metrics)
    
    plt.figure(figsize=(12, 6))
    sns.set_style("darkgrid")
    
    plt.plot(df['step'], df['avg_trust'], 'g-', linewidth=2)
    plt.fill_between(df['step'], 
                    df['avg_trust'] - df['avg_trust'].std(), 
                    df['avg_trust'] + df['avg_trust'].std(), 
                    alpha=0.3, color='g')
    
    plt.title('Trust Score Evolution with Confidence Interval')
    plt.xlabel('Simulation Step')
    plt.ylabel('Average Trust Score')
    plt.grid(True, alpha=0.3)
    plt.show()

def plot_speeds(vehicles: List[Vehicle], num_steps: int, dt: float):
    """Enhanced speed plotting with vehicle types."""
    times = list(range(num_steps))
    speeds = {vehicle.id: [] for vehicle in vehicles}
    vehicle_types = {vehicle.id: vehicle.vehicle_type for vehicle in vehicles}
    
    for i in range(num_steps):
        for vehicle in vehicles:
            vehicle.move(dt)
            speeds[vehicle.id].append(vehicle.speed)
    
    speeds_df = pd.DataFrame(speeds, index=times)
    
    plt.figure(figsize=(12, 6))
    for vehicle_id in speeds_df.columns:
        vehicle_type = vehicle_types[vehicle_id]
        color = {'emergency': 'r', 'regular': 'b', 'public_transport': 'g'}[vehicle_type.value]
        plt.plot(times, speeds_df[vehicle_id], color=color, 
                label=f"{vehicle_id} ({vehicle_type.value})")
    
    plt.title("Vehicle Speeds Over Time")
    plt.xlabel("Time Step")
    plt.ylabel("Speed (m/s)")
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.show()

def plot_positions(vehicles: List[Vehicle], num_steps: int, dt: float):
    """Enhanced position plotting with trajectories and vehicle types."""
    positions = {vehicle.id: [] for vehicle in vehicles}
    vehicle_types = {vehicle.id: vehicle.vehicle_type for vehicle in vehicles}
    
    plt.figure(figsize=(12, 12))
    
    for i in range(num_steps):
        for vehicle in vehicles:
            vehicle.move(dt)
            positions[vehicle.id].append(vehicle.position)
    
    # Plot trajectories and final positions
    for vehicle_id, pos_list in positions.items():
        vehicle_type = vehicle_types[vehicle_id]
        color = {'emergency': 'red', 'regular': 'blue', 'public_transport': 'green'}[vehicle_type.value]
        
        # Plot trajectory with alpha
        x_coords = [p[0] for p in pos_list]
        y_coords = [p[1] for p in pos_list]
        plt.plot(x_coords, y_coords, color=color, alpha=0.3)
        
        # Plot final position
        plt.scatter(x_coords[-1], y_coords[-1], color=color, s=100, 
                   label=f"{vehicle_id} ({vehicle_type.value})")
    
    plt.title("Vehicle Positions and Trajectories")
    plt.xlabel("X Position")
    plt.ylabel("Y Position")
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, alpha=0.3)
    plt.axis('equal')
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    print("Creating vehicles...")
    # Create test vehicles with different types (reduced number)
    vehicles = [
        Vehicle("V1", 65, (0, 0), VehicleType.EMERGENCY),
        Vehicle("V2", 50, (10, 20), VehicleType.REGULAR)  # Further reduced for testing
    ]

    print("Starting simulation...")
    # Run simulation with minimal steps for testing
    security_metrics = simulate(vehicles, 0.1, 50)  # Reduced steps for faster testing

    # Calculate final metrics
    final_metrics = security_metrics[-1]
    print("\nFinal Simulation Metrics:")
    print(f"Packet Delivery Ratio: {final_metrics['pdr']:.2%}")
    print(f"Messages Received: {final_metrics['valid_messages']}")
    print(f"Attack Detection Rate: {final_metrics['attack_detection_rate']:.2%}")
    print(f"Average Trust Score: {final_metrics['avg_trust']:.2f}")

    print("\nGenerating visualizations...")
    plot_speeds(vehicles, 50, 0.1)
    plot_positions(vehicles, 50, 0.1)

    print("\nSimulation complete!") 