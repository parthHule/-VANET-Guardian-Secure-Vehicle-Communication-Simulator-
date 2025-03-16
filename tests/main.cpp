#include "../src/routing/secure-routing.h"
#include <iostream>
#include <cassert>
#include <chrono>
#include <thread>

using namespace vanet;
using namespace std::chrono;

void testCryptoModule() {
    crypto::CryptoModule crypto;
    
    // Test key generation
    assert(crypto.generateKeyPair());
    
    // Test message hashing
    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    auto hash = crypto.hashMessage(message);
    assert(!hash.empty());
    
    // Test message signing and verification
    auto signature = crypto.signMessage(message);
    assert(!signature.empty());
    
    // Create and verify secure message
    auto secureMsg = crypto.createSecureMessage(message);
    assert(crypto.verifySecureMessage(secureMsg));
}

void testSecureRouting() {
    routing::SecureRoutingProtocol router("test_vehicle");
    
    // Initialize vehicle
    routing::VehicleInfo info;
    info.id = "test_vehicle";
    info.position = {0.0, 0.0, 0.0, system_clock::now()};
    info.speed = 50.0;
    info.direction = 0.0;
    info.trustScore = 1.0;
    
    assert(router.initializeVehicle(info));
    
    // Test position update
    routing::Position newPos = {10.0, 0.0, 0.0, system_clock::now()};
    assert(router.updatePosition(newPos));
    
    // Test invalid position update (too fast)
    routing::Position invalidPos = {1000.0, 0.0, 0.0, system_clock::now()};
    assert(!router.updatePosition(invalidPos));
    
    // Test route management
    routing::RouteEntry entry;
    entry.nextHop = "neighbor1";
    entry.hopCount = 1;
    entry.timestamp = system_clock::now();
    entry.trustScore = 1.0;
    
    assert(router.updateRoute("destination1", entry));
    
    // Test trust management
    assert(router.isVehicleTrusted("neighbor1"));
    router.updateTrustScore("neighbor1", 0.3);
    assert(!router.isVehicleTrusted("neighbor1"));
}

void testAttackDetection() {
    routing::SecureRoutingProtocol router("test_vehicle");
    
    // Initialize vehicle
    routing::VehicleInfo info;
    info.id = "test_vehicle";
    info.position = {0.0, 0.0, 0.0, system_clock::now()};
    
    router.initializeVehicle(info);
    
    // Test position falsification detection
    routing::Position validPos = {10.0, 0.0, 0.0, system_clock::now()};
    router.updatePosition(validPos);
    
    std::this_thread::sleep_for(milliseconds(100));
    
    routing::Position invalidPos = {1000.0, 0.0, 0.0, system_clock::now()};
    assert(router.detectPositionFalsification("test_vehicle", invalidPos));
    
    // Test replay attack detection
    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    assert(!router.detectReplay(message));
    assert(router.detectReplay(message)); // Second time should detect replay
}

int main() {
    try {
        std::cout << "Running crypto module tests..." << std::endl;
        testCryptoModule();
        std::cout << "Crypto module tests passed!" << std::endl;
        
        std::cout << "Running secure routing tests..." << std::endl;
        testSecureRouting();
        std::cout << "Secure routing tests passed!" << std::endl;
        
        std::cout << "Running attack detection tests..." << std::endl;
        testAttackDetection();
        std::cout << "Attack detection tests passed!" << std::endl;
        
        std::cout << "All tests passed successfully!" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with error: " << e.what() << std::endl;
        return 1;
    }
} 