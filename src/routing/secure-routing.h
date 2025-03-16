#ifndef VANET_SECURE_ROUTING_H
#define VANET_SECURE_ROUTING_H

#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include "../crypto/crypto-module.h"

namespace vanet {
namespace routing {

struct Position {
    double x;
    double y;
    double z;
    std::chrono::system_clock::time_point timestamp;
};

struct VehicleInfo {
    std::string id;
    Position position;
    double speed;
    double direction;
    double trustScore;
    std::vector<uint8_t> certificate;
};

struct RouteEntry {
    std::string nextHop;
    uint32_t hopCount;
    std::chrono::system_clock::time_point timestamp;
    double trustScore;
};

enum class MessageType {
    HELLO,
    ROUTE_REQUEST,
    ROUTE_REPLY,
    ROUTE_ERROR,
    DATA
};

class SecureRoutingProtocol {
public:
    SecureRoutingProtocol(const std::string& vehicleId);
    ~SecureRoutingProtocol();

    // Core routing functions
    bool initializeVehicle(const VehicleInfo& info);
    bool updatePosition(const Position& newPos);
    bool sendData(const std::string& destination, const std::vector<uint8_t>& data);
    bool receiveMessage(const std::vector<uint8_t>& message);

    // Route management
    bool findRoute(const std::string& destination);
    bool updateRoute(const std::string& destination, const RouteEntry& entry);
    bool invalidateRoute(const std::string& destination);

    // Trust management
    double calculateTrust(const std::string& vehicleId);
    void updateTrustScore(const std::string& vehicleId, double score);
    bool isVehicleTrusted(const std::string& vehicleId);

    // Beacon management
    void sendBeacon();
    bool processBeacon(const std::vector<uint8_t>& beacon);

    // Attack detection
    bool detectBlackHole(const std::string& suspectId);
    bool detectSybil(const std::string& suspectId);
    bool detectReplay(const std::vector<uint8_t>& message);
    bool detectPositionFalsification(const std::string& vehicleId, const Position& reportedPos);

private:
    std::string vehicleId;
    VehicleInfo localInfo;
    std::unique_ptr<crypto::CryptoModule> cryptoModule;
    
    // Routing tables and caches
    std::map<std::string, RouteEntry> routingTable;
    std::map<std::string, VehicleInfo> neighborTable;
    std::map<std::string, double> trustScores;
    
    // Message sequence tracking
    struct MessageTracker {
        uint32_t lastSequence;
        std::chrono::system_clock::time_point lastUpdate;
    };
    std::map<std::string, MessageTracker> messageTracking;

    // Helper functions
    std::vector<uint8_t> createRoutingMessage(MessageType type, const std::string& destination);
    bool verifyRoutingMessage(const std::vector<uint8_t>& message);
    double calculateDistance(const Position& pos1, const Position& pos2);
    bool isValidMovement(const Position& oldPos, const Position& newPos, double timeElapsed);
    void pruneExpiredEntries();
};

} // namespace routing
} // namespace vanet

#endif // VANET_SECURE_ROUTING_H 