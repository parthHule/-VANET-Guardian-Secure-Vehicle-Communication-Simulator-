from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import time
import math
from ..crypto.crypto_module import CryptoModule, SecureMessage

@dataclass
class Position:
    x: float
    y: float
    z: float
    timestamp: float

@dataclass
class VehicleInfo:
    id: str
    position: Position
    speed: float
    direction: float
    trust_score: float
    certificate: Optional[bytes] = None

@dataclass
class RouteEntry:
    next_hop: str
    hop_count: int
    timestamp: float
    trust_score: float

class MessageType:
    HELLO = 0
    ROUTE_REQUEST = 1
    ROUTE_REPLY = 2
    ROUTE_ERROR = 3
    DATA = 4

class SecureRoutingProtocol:
    def __init__(self, vehicle_id: str):
        self.vehicle_id = vehicle_id
        self.crypto_module = CryptoModule()
        self.local_info = None
        self.routing_table: Dict[str, RouteEntry] = {}
        self.neighbor_table: Dict[str, VehicleInfo] = {}
        self.trust_scores: Dict[str, float] = {}
        self.message_tracking: Dict[str, Tuple[int, float]] = {}  # (last_sequence, last_update)
        
        # Constants
        self.MAX_TRUST_SCORE = 1.0
        self.MIN_TRUST_SCORE = 0.0
        self.TRUST_THRESHOLD = 0.5
        self.MAX_SPEED = 200.0  # km/h
        self.MAX_ACCELERATION = 10.0  # m/s²
        self.ROUTE_TIMEOUT = 60  # seconds
        self.NEIGHBOR_TIMEOUT = 10  # seconds
        self.MAX_HOP_COUNT = 10
        
        # Initialize cryptographic keys
        self.crypto_module.generate_key_pair()

    def initialize_vehicle(self, info: VehicleInfo) -> bool:
        """Initialize the vehicle with its information."""
        if info.id != self.vehicle_id:
            return False
        
        self.local_info = info
        return True

    def update_position(self, new_pos: Position) -> bool:
        """Update vehicle's position if the movement is valid."""
        if not self.local_info:
            return False
            
        if not self._is_valid_movement(self.local_info.position, new_pos):
            return False
            
        self.local_info.position = new_pos
        self._prune_expired_entries()
        return True

    def send_data(self, destination: str, data: bytes) -> bool:
        """Send data to a destination using secure routing."""
        # Check if we have a route
        route = self.routing_table.get(destination)
        if not route:
            if not self.find_route(destination):
                return False
            route = self.routing_table.get(destination)
            
        if not route or not self.is_vehicle_trusted(route.next_hop):
            return False
            
        # Create secure message
        message = self._create_routing_message(MessageType.DATA, destination, data)
        secure_message = self.crypto_module.create_secure_message(message)
        
        # In a real implementation, this would send the message to the next hop
        # For simulation, we'll just return True
        return True

    def receive_message(self, message: bytes) -> bool:
        """Process received message."""
        try:
            secure_message = self._deserialize_message(message)
            if not self.crypto_module.verify_secure_message(secure_message):
                return False
                
            message_type = message[0]
            if message_type == MessageType.HELLO:
                return self.process_beacon(secure_message.payload)
            elif message_type == MessageType.ROUTE_REQUEST:
                # Handle route request
                pass
            elif message_type == MessageType.ROUTE_REPLY:
                # Handle route reply
                pass
            elif message_type == MessageType.ROUTE_ERROR:
                # Handle route error
                pass
            elif message_type == MessageType.DATA:
                # Handle data message
                pass
                
            return True
        except Exception as e:
            print(f"Error processing message: {e}")
            return False

    def find_route(self, destination: str) -> bool:
        """Initiate route discovery to destination."""
        message = self._create_routing_message(MessageType.ROUTE_REQUEST, destination)
        secure_message = self.crypto_module.create_secure_message(message)
        
        # In a real implementation, this would broadcast the route request
        # For simulation, we'll just return True
        return True

    def update_route(self, destination: str, entry: RouteEntry) -> bool:
        """Update routing table entry."""
        if entry.hop_count >= self.MAX_HOP_COUNT:
            return False
            
        if time.time() - entry.timestamp > self.ROUTE_TIMEOUT:
            return False
            
        self.routing_table[destination] = entry
        return True

    def calculate_trust(self, vehicle_id: str) -> float:
        """Calculate trust score for a vehicle."""
        if vehicle_id not in self.trust_scores:
            return self.MIN_TRUST_SCORE
            
        score = self.trust_scores[vehicle_id]
        
        # Check for suspicious behavior
        if self.detect_black_hole(vehicle_id) or self.detect_sybil(vehicle_id):
            score *= 0.5
            
        # Verify position consistency
        if vehicle_id in self.neighbor_table:
            if self.detect_position_falsification(vehicle_id, self.neighbor_table[vehicle_id].position):
                score *= 0.5
                
        return max(min(score, self.MAX_TRUST_SCORE), self.MIN_TRUST_SCORE)

    def update_trust_score(self, vehicle_id: str, score: float):
        """Update trust score using exponential moving average."""
        current_score = self.trust_scores.get(vehicle_id, self.MAX_TRUST_SCORE)
        alpha = 0.3  # Weight for new score
        self.trust_scores[vehicle_id] = (alpha * score) + ((1 - alpha) * current_score)

    def is_vehicle_trusted(self, vehicle_id: str) -> bool:
        """Check if a vehicle's trust score is above threshold."""
        return self.calculate_trust(vehicle_id) >= self.TRUST_THRESHOLD

    def send_beacon(self):
        """Send periodic beacon message."""
        message = self._create_routing_message(MessageType.HELLO, "")
        secure_message = self.crypto_module.create_secure_message(message)
        
        # In a real implementation, this would broadcast the beacon
        # For simulation, we'll just pass

    def process_beacon(self, beacon: bytes) -> bool:
        """Process received beacon message."""
        try:
            info = self._deserialize_vehicle_info(beacon)
            if not info:
                return False
                
            self.neighbor_table[info.id] = info
            self.update_trust_score(info.id, 1.0)
            return True
        except Exception:
            return False

    def detect_black_hole(self, suspect_id: str) -> bool:
        """Detect black hole attack behavior."""
        # Implementation would track packet forwarding rates
        # and route advertisement patterns
        return False

    def detect_sybil(self, suspect_id: str) -> bool:
        """Detect Sybil attack behavior."""
        # Implementation would check for multiple identities
        # from similar positions
        return False

    def detect_position_falsification(self, vehicle_id: str, reported_pos: Position) -> bool:
        """Detect position falsification attack."""
        if vehicle_id not in self.neighbor_table:
            return False
            
        last_pos = self.neighbor_table[vehicle_id].position
        time_elapsed = reported_pos.timestamp - last_pos.timestamp
        
        return not self._is_valid_movement(last_pos, reported_pos)

    def _create_routing_message(self, msg_type: int, destination: str, data: bytes = b"") -> bytes:
        """Create a routing message."""
        message = bytearray([msg_type])
        message.extend(self.vehicle_id.encode())
        message.append(0)  # null terminator
        message.extend(destination.encode())
        message.append(0)  # null terminator
        message.extend(str(time.time()).encode())
        if data:
            message.extend(data)
        return bytes(message)

    def _deserialize_message(self, message: bytes) -> SecureMessage:
        """Deserialize a received message."""
        # Implementation depends on your message format
        # This is a simplified example
        return SecureMessage(
            payload=message,
            signature=b"",
            timestamp=time.time(),
            sequence_number=0
        )

    def _deserialize_vehicle_info(self, data: bytes) -> Optional[VehicleInfo]:
        """Deserialize vehicle information from bytes."""
        # Implementation depends on your message format
        # This is a simplified example
        return None

    def _is_valid_movement(self, old_pos: Position, new_pos: Position) -> bool:
        """Check if movement between positions is physically possible."""
        if not old_pos or not new_pos:
            return True
            
        time_elapsed = new_pos.timestamp - old_pos.timestamp
        if time_elapsed <= 0:
            return False
            
        distance = self._calculate_distance(old_pos, new_pos)
        speed = distance / time_elapsed
        
        # Convert speed to km/h
        speed = speed * 3.6
        
        # Check if speed is within reasonable limits
        if speed > self.MAX_SPEED:
            return False
            
        # Check acceleration
        acceleration = speed / time_elapsed
        return acceleration <= self.MAX_ACCELERATION

    def _calculate_distance(self, pos1: Position, pos2: Position) -> float:
        """Calculate Euclidean distance between two positions."""
        return math.sqrt(
            (pos1.x - pos2.x) ** 2 +
            (pos1.y - pos2.y) ** 2 +
            (pos1.z - pos2.z) ** 2
        )

    def _prune_expired_entries(self):
        """Remove expired entries from routing and neighbor tables."""
        current_time = time.time()
        
        # Prune routing table
        expired_routes = [
            dest for dest, entry in self.routing_table.items()
            if current_time - entry.timestamp > self.ROUTE_TIMEOUT
        ]
        for dest in expired_routes:
            del self.routing_table[dest]
            
        # Prune neighbor table
        expired_neighbors = [
            vid for vid, info in self.neighbor_table.items()
            if current_time - info.position.timestamp > self.NEIGHBOR_TIMEOUT
        ]
        for vid in expired_neighbors:
            del self.neighbor_table[vid] 