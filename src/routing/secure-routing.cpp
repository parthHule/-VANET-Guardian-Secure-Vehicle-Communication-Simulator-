#include "secure-routing.h"
#include <cmath>
#include <algorithm>
#include <stdexcept>
#include <sstream>

namespace vanet {
namespace routing {

// Constants for protocol parameters
constexpr double MAX_TRUST_SCORE = 1.0;
constexpr double MIN_TRUST_SCORE = 0.0;
constexpr double TRUST_THRESHOLD = 0.5;
constexpr double MAX_SPEED = 200.0; // km/h
constexpr double MAX_ACCELERATION = 10.0; // m/s^2
constexpr std::chrono::seconds ROUTE_TIMEOUT(60);
constexpr std::chrono::seconds NEIGHBOR_TIMEOUT(10);
constexpr uint32_t MAX_HOP_COUNT = 10;

SecureRoutingProtocol::SecureRoutingProtocol(const std::string& id) 
    : vehicleId(id), cryptoModule(std::make_unique<crypto::CryptoModule>()) {
    localInfo.id = id;
    localInfo.trustScore = MAX_TRUST_SCORE;
}

SecureRoutingProtocol::~SecureRoutingProtocol() = default;

bool SecureRoutingProtocol::initializeVehicle(const VehicleInfo& info) {
    if (info.id != vehicleId) {
        return false;
    }
    
    localInfo = info;
    return cryptoModule->generateKeyPair();
}

bool SecureRoutingProtocol::updatePosition(const Position& newPos) {
    if (!isValidMovement(localInfo.position, newPos, 
        std::chrono::duration_cast<std::chrono::seconds>(
            newPos.timestamp - localInfo.position.timestamp).count())) {
        return false;
    }
    
    localInfo.position = newPos;
    pruneExpiredEntries();
    return true;
}

bool SecureRoutingProtocol::sendData(const std::string& destination, const std::vector<uint8_t>& data) {
    auto routeIt = routingTable.find(destination);
    if (routeIt == routingTable.end()) {
        if (!findRoute(destination)) {
            return false;
        }
        routeIt = routingTable.find(destination);
    }
    
    if (!isVehicleTrusted(routeIt->second.nextHop)) {
        invalidateRoute(destination);
        return false;
    }
    
    // Create secure message
    auto message = createRoutingMessage(MessageType::DATA, destination);
    message.insert(message.end(), data.begin(), data.end());
    
    // Sign and encrypt using crypto module
    auto secureMessage = cryptoModule->createSecureMessage(message);
    
    // Send to next hop (implementation depends on network layer)
    // For simulation purposes, this would interface with NS-3
    return true;
}

bool SecureRoutingProtocol::receiveMessage(const std::vector<uint8_t>& message) {
    if (!verifyRoutingMessage(message)) {
        return false;
    }
    
    // Extract message type and handle accordingly
    MessageType type = static_cast<MessageType>(message[0]);
    switch (type) {
        case MessageType::HELLO:
            return processBeacon(message);
        case MessageType::ROUTE_REQUEST:
            // Handle route request
            break;
        case MessageType::ROUTE_REPLY:
            // Handle route reply
            break;
        case MessageType::ROUTE_ERROR:
            // Handle route error
            break;
        case MessageType::DATA:
            // Handle data message
            break;
    }
    
    return true;
}

bool SecureRoutingProtocol::findRoute(const std::string& destination) {
    // Create RREQ message
    auto rreq = createRoutingMessage(MessageType::ROUTE_REQUEST, destination);
    
    // Sign message
    auto secureRreq = cryptoModule->createSecureMessage(rreq);
    
    // Broadcast to neighbors (implementation depends on network layer)
    // For simulation purposes, this would interface with NS-3
    
    return true;
}

bool SecureRoutingProtocol::updateRoute(const std::string& destination, const RouteEntry& entry) {
    if (entry.hopCount >= MAX_HOP_COUNT) {
        return false;
    }
    
    auto now = std::chrono::system_clock::now();
    if (entry.timestamp + ROUTE_TIMEOUT < now) {
        return false;
    }
    
    routingTable[destination] = entry;
    return true;
}

bool SecureRoutingProtocol::invalidateRoute(const std::string& destination) {
    auto it = routingTable.find(destination);
    if (it != routingTable.end()) {
        routingTable.erase(it);
        
        // Create and broadcast RERR message
        auto rerr = createRoutingMessage(MessageType::ROUTE_ERROR, destination);
        auto secureRerr = cryptoModule->createSecureMessage(rerr);
        
        // Broadcast RERR (implementation depends on network layer)
        return true;
    }
    return false;
}

double SecureRoutingProtocol::calculateTrust(const std::string& vehicleId) {
    auto it = trustScores.find(vehicleId);
    if (it == trustScores.end()) {
        return MIN_TRUST_SCORE;
    }
    
    // Factor in various trust metrics
    double score = it->second;
    
    // Check for suspicious behavior
    if (detectBlackHole(vehicleId) || detectSybil(vehicleId)) {
        score *= 0.5;
    }
    
    // Verify position consistency
    auto neighborIt = neighborTable.find(vehicleId);
    if (neighborIt != neighborTable.end()) {
        if (detectPositionFalsification(vehicleId, neighborIt->second.position)) {
            score *= 0.5;
        }
    }
    
    return std::clamp(score, MIN_TRUST_SCORE, MAX_TRUST_SCORE);
}

void SecureRoutingProtocol::updateTrustScore(const std::string& vehicleId, double score) {
    double currentScore = trustScores[vehicleId];
    // Use exponential moving average
    constexpr double alpha = 0.3;
    trustScores[vehicleId] = (alpha * score) + ((1 - alpha) * currentScore);
}

bool SecureRoutingProtocol::isVehicleTrusted(const std::string& vehicleId) {
    return calculateTrust(vehicleId) >= TRUST_THRESHOLD;
}

void SecureRoutingProtocol::sendBeacon() {
    auto beacon = createRoutingMessage(MessageType::HELLO, "");
    auto secureBeacon = cryptoModule->createSecureMessage(beacon);
    
    // Broadcast beacon (implementation depends on network layer)
}

bool SecureRoutingProtocol::processBeacon(const std::vector<uint8_t>& beacon) {
    // Extract vehicle info from beacon
    VehicleInfo info;
    // ... parse beacon data ...
    
    // Verify certificate
    if (!cryptoModule->verifySecureMessage(crypto::CryptoModule::SecureMessage{/*...*/})) {
        return false;
    }
    
    // Update neighbor table
    neighborTable[info.id] = info;
    
    // Update trust score based on beacon validity
    updateTrustScore(info.id, 1.0);
    
    return true;
}

bool SecureRoutingProtocol::detectBlackHole(const std::string& suspectId) {
    // Check for abnormally high route advertisements
    // and low packet forwarding rates
    return false;
}

bool SecureRoutingProtocol::detectSybil(const std::string& suspectId) {
    // Check for multiple identities from similar positions
    // or with similar certificates
    return false;
}

bool SecureRoutingProtocol::detectReplay(const std::vector<uint8_t>& message) {
    return cryptoModule->isReplayMessage(crypto::CryptoModule::SecureMessage{/*...*/});
}

bool SecureRoutingProtocol::detectPositionFalsification(const std::string& vehicleId, const Position& reportedPos) {
    auto it = neighborTable.find(vehicleId);
    if (it == neighborTable.end()) {
        return false;
    }
    
    const auto& lastPos = it->second.position;
    double timeElapsed = std::chrono::duration_cast<std::chrono::seconds>(
        reportedPos.timestamp - lastPos.timestamp).count();
    
    return !isValidMovement(lastPos, reportedPos, timeElapsed);
}

std::vector<uint8_t> SecureRoutingProtocol::createRoutingMessage(MessageType type, const std::string& destination) {
    std::vector<uint8_t> message;
    message.push_back(static_cast<uint8_t>(type));
    
    // Add source ID
    message.insert(message.end(), vehicleId.begin(), vehicleId.end());
    message.push_back(0); // null terminator
    
    // Add destination ID
    message.insert(message.end(), destination.begin(), destination.end());
    message.push_back(0); // null terminator
    
    // Add timestamp
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    message.insert(message.end(),
        reinterpret_cast<uint8_t*>(&timestamp),
        reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));
    
    return message;
}

bool SecureRoutingProtocol::verifyRoutingMessage(const std::vector<uint8_t>& message) {
    if (message.empty()) {
        return false;
    }
    
    // Verify message structure
    MessageType type = static_cast<MessageType>(message[0]);
    if (type > MessageType::DATA) {
        return false;
    }
    
    // Verify signature and certificate
    return cryptoModule->verifySecureMessage(crypto::CryptoModule::SecureMessage{/*...*/});
}

double SecureRoutingProtocol::calculateDistance(const Position& pos1, const Position& pos2) {
    double dx = pos1.x - pos2.x;
    double dy = pos1.y - pos2.y;
    double dz = pos1.z - pos2.z;
    return std::sqrt(dx*dx + dy*dy + dz*dz);
}

bool SecureRoutingProtocol::isValidMovement(const Position& oldPos, const Position& newPos, double timeElapsed) {
    if (timeElapsed <= 0) {
        return false;
    }
    
    double distance = calculateDistance(oldPos, newPos);
    double speed = distance / timeElapsed;
    
    // Convert speed to km/h
    speed = speed * 3.6;
    
    // Check if speed is within reasonable limits
    if (speed > MAX_SPEED) {
        return false;
    }
    
    // Check acceleration
    double acceleration = speed / timeElapsed;
    return acceleration <= MAX_ACCELERATION;
}

void SecureRoutingProtocol::pruneExpiredEntries() {
    auto now = std::chrono::system_clock::now();
    
    // Prune routing table
    for (auto it = routingTable.begin(); it != routingTable.end();) {
        if (it->second.timestamp + ROUTE_TIMEOUT < now) {
            it = routingTable.erase(it);
        } else {
            ++it;
        }
    }
    
    // Prune neighbor table
    for (auto it = neighborTable.begin(); it != neighborTable.end();) {
        if (it->second.position.timestamp + NEIGHBOR_TIMEOUT < now) {
            it = neighborTable.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace routing
} // namespace vanet 