#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "../src/routing/secure-routing.h"

using namespace ns3;
using namespace vanet;

NS_LOG_COMPONENT_DEFINE("VanetSecureRoutingSimulation");

class VanetNode {
public:
    VanetNode(const std::string& id, Ptr<Node> node)
        : id(id), node(node), router(id) {
        
        routing::VehicleInfo info;
        info.id = id;
        Vector pos = node->GetObject<MobilityModel>()->GetPosition();
        info.position = {pos.x, pos.y, pos.z, 
                        std::chrono::system_clock::now()};
        
        router.initializeVehicle(info);
    }
    
    void UpdatePosition() {
        Vector pos = node->GetObject<MobilityModel>()->GetPosition();
        routing::Position newPos = {
            pos.x, pos.y, pos.z,
            std::chrono::system_clock::now()
        };
        router.updatePosition(newPos);
    }
    
    void SendData(const std::string& destId, const std::vector<uint8_t>& data) {
        router.sendData(destId, data);
    }
    
    void ReceiveData(Ptr<Packet> packet) {
        uint8_t buffer[packet->GetSize()];
        packet->CopyData(buffer, packet->GetSize());
        std::vector<uint8_t> data(buffer, buffer + packet->GetSize());
        
        router.receiveMessage(data);
    }
    
private:
    std::string id;
    Ptr<Node> node;
    routing::SecureRoutingProtocol router;
};

int main(int argc, char *argv[]) {
    // Enable logging
    LogComponentEnable("VanetSecureRoutingSimulation", LOG_LEVEL_INFO);
    
    // Simulation parameters
    uint32_t numVehicles = 50;
    uint32_t numMalicious = 5;
    double simTime = 300.0; // seconds
    
    CommandLine cmd;
    cmd.AddValue("numVehicles", "Number of vehicles", numVehicles);
    cmd.AddValue("numMalicious", "Number of malicious nodes", numMalicious);
    cmd.AddValue("simTime", "Simulation time in seconds", simTime);
    cmd.Parse(argc, argv);
    
    // Create nodes
    NodeContainer vehicles;
    vehicles.Create(numVehicles);
    
    // Set up WiFi
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());
    
    WifiMacHelper mac;
    WifiHelper wifi;
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue("OfdmRate6Mbps"),
                                "ControlMode", StringValue("OfdmRate6Mbps"));
    
    NetDeviceContainer devices = wifi.Install(phy, mac, vehicles);
    
    // Set up internet stack
    InternetStackHelper internet;
    internet.Install(vehicles);
    
    // Set up mobility
    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::RandomBoxPositionAllocator",
                                 "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                 "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                 "Z", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=0.0]"));
    
    mobility.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                             "Speed", StringValue("ns3::UniformRandomVariable[Min=20.0|Max=50.0]"),
                             "Pause", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"),
                             "PositionAllocator", StringValue("ns3::RandomBoxPositionAllocator"));
    
    mobility.Install(vehicles);
    
    // Create VANET nodes
    std::vector<VanetNode> vanetNodes;
    for (uint32_t i = 0; i < numVehicles; ++i) {
        std::string id = "vehicle_" + std::to_string(i);
        vanetNodes.emplace_back(id, vehicles.Get(i));
    }
    
    // Schedule position updates
    for (uint32_t i = 0; i < numVehicles; ++i) {
        Simulator::Schedule(Seconds(1.0), &VanetNode::UpdatePosition, &vanetNodes[i]);
    }
    
    // Set up malicious nodes
    std::set<uint32_t> maliciousIndices;
    while (maliciousIndices.size() < numMalicious) {
        maliciousIndices.insert(rand() % numVehicles);
    }
    
    // Schedule data transmissions
    for (uint32_t i = 0; i < numVehicles; ++i) {
        if (maliciousIndices.find(i) == maliciousIndices.end()) {
            // Regular node behavior
            Simulator::Schedule(Seconds(10.0 + (rand() % 30)),
                              &VanetNode::SendData,
                              &vanetNodes[i],
                              "vehicle_" + std::to_string((i + 1) % numVehicles),
                              std::vector<uint8_t>{'t', 'e', 's', 't'});
        } else {
            // Malicious node behavior - implement attack scenarios
            // TODO: Implement different attack patterns
        }
    }
    
    // Enable packet tracing
    AsciiTraceHelper ascii;
    phy.EnableAsciiAll(ascii.CreateFileStream("vanet-trace.tr"));
    
    // Enable animation
    AnimationInterface anim("vanet-animation.xml");
    
    // Run simulation
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();
    
    return 0;
} 