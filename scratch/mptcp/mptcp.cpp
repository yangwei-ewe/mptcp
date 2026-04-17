/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * MPTCP multipath example
 *
 * Topology
 *
 *        n0 ================= n1
 *         |        |        |
 *       path1    path2    path3
 *
 * Each path has a different subnet.
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"

#include <sstream>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("MpTcpMultipathExample");

int main(int argc, char* argv[]) {
    // LogComponentEnable("MpTcpPacketSink", LOG_LEVEL_DEBUG);
    LogComponentEnable("MpTcpBulkSendApplication", LOG_LEVEL_DEBUG);
    // LogComponentEnable("MpTcpSocketBase", LOG_LEVEL_ALL);
    // LogComponentEnable("MpTcpTypeDefs", LOG_LEVEL_ALL);

    /* ----------- TCP / MPTCP configuration ----------- */

    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1400));
    Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(0));
    Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(128));

    Config::SetDefault("ns3::TcpL4Protocol::SocketType", TypeIdValue(MpTcpSocketBase::GetTypeId()));

    Config::SetDefault("ns3::MpTcpSocketBase::MaxSubflows", UintegerValue(8));
    Config::SetDefault("ns3::MpTcpSocketBase::CheckAlgorithm", EnumValue(HMAC_MURMUR3));

    /* ----------- Create nodes ----------- */

    NodeContainer nodes;
    nodes.Create(2);

    /* ----------- Install internet stack ----------- */

    InternetStackHelper internet;
    internet.Install(nodes);

    /* ----------- Create multiple paths ----------- */

    Ipv4AddressHelper ipv4;
    // --- 第一條鏈路 (10.1.1.0) ---
    PointToPointHelper p2p1;
    p2p1.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p1.SetChannelAttribute("Delay", StringValue("10ms"));
    NetDeviceContainer dev1 = p2p1.Install(nodes);
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer i = ipv4.Assign(dev1);

    // // --- 第二條鏈路 (10.1.2.0) ---
    // PointToPointHelper p2p2;
    // p2p2.SetDeviceAttribute("DataRate", StringValue("20Mbps"));
    // p2p2.SetChannelAttribute("Delay", StringValue("10ms"));
    // NetDeviceContainer dev2 = p2p2.Install(nodes);
    // ipv4.SetBase("10.1.2.0", "255.255.255.0");
    // ipv4.Assign(dev2);
    // Ipv4InterfaceContainer i2 = ipv4.Assign(dev2); // second ip on this route

    // --- 第三條鏈路 (10.1.3.0) ---
    // PointToPointHelper p2p3;
    // p2p3.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    // p2p3.SetChannelAttribute("Delay", StringValue("10ms"));
    // NetDeviceContainer dev3 = p2p3.Install(nodes);
    // ipv4.SetBase("10.1.3.0", "255.255.255.0");
    // ipv4.Assign(dev3);

    /* ----------- Routing ----------- */

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    /* ----------- Applications ----------- */

    uint16_t port = 5000;

    MpTcpPacketSinkHelper sink("ns3::TcpSocketFactory",
                               InetSocketAddress(Ipv4Address::GetAny(), port));

    ApplicationContainer sinkApps = sink.Install(nodes.Get(1));
    sinkApps.Stop(Seconds(20.0));

    MpTcpBulkSendHelper source("ns3::TcpSocketFactory",
                               InetSocketAddress(Ipv4Address(i.GetAddress(1)), port));
    // source.SetAttribute("MaxBytes", UintegerValue(0));  // send forever
    // source.SetAttribute("MaxBytes", UintegerValue(1e5));
    source.SetAttribute("SendSize", UintegerValue(100));

    ApplicationContainer sourceApps = source.Install(nodes.Get(0));
    sourceApps.Start(Seconds(0.0));
    sourceApps.Stop(Seconds(20.0));

    /* ----------- Run simulation ----------- */

    NS_LOG_INFO("Run Simulation");

    Simulator::Stop(Seconds(20.0));
    Simulator::Run();
    Simulator::Destroy();

    NS_LOG_INFO("Simulation finished");

    return 0;
}
