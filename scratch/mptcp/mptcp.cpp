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
    LogComponentEnable("MpTcpPacketSink", LOG_LEVEL_DEBUG);
    // LogComponentEnable("MpTcpBulkSendApplication", LOG_LEVEL_DEBUG);
    LogComponentEnable("MpTcpSocketBase", LOG_LEVEL_ALL);
    // LogComponentEnable("MpTcpTypeDefs", LOG_LEVEL_ALL);
    // LogComponentEnable("fec", LOG_LEVEL_ALL);
    // LogComponentEnable("TcpOptionIR", LOG_LEVEL_ALL);

    // LogComponentEnable("Ipv4EndPointDemux", LOG_LEVEL_ALL);
    // LogComponentEnable("TcpL4Protocol", LOG_LEVEL_ALL);
    // LogComponentEnable("TcpSocketBase", LOG_LEVEL_ALL);
    // LogComponentEnable("MpTcpSubflow", LOG_LEVEL_ALL);

    /* ----------- TCP / MPTCP configuration ----------- */

    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1436)); // relate to MSS
    Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(0));
    Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(32768)); // 32k
    Config::SetDefault("ns3::MpTcpSocketBase::FecEnable", BooleanValue(true));
    // Config::SetDefault("ns3::MpTcpSocketBase::FecAlgorithm", EnumValue(ReedSolomon));
    Config::SetDefault("ns3::MpTcpSocketBase::FecBlockSize", UintegerValue(6));

    Config::SetDefault("ns3::TcpL4Protocol::SocketType", TypeIdValue(MpTcpSocketBase::GetTypeId()));

    Config::SetDefault("ns3::MpTcpSocketBase::MaxSubflows", UintegerValue(8));
    Config::SetDefault("ns3::MpTcpSocketBase::CheckAlgorithm", EnumValue(HMAC_MURMUR3));
    // Config::SetDefault("ns3::MpTcpBulkSendApplication::MaxBytes", UintegerValue(0));

    RngSeedManager::SetSeed(time(NULL));

    /* ----------- Create nodes ----------- */

    NodeContainer nodes;
    nodes.Create(2); // two nodes

    /* ----------- Install internet stack ----------- */

    InternetStackHelper internet;
    internet.Install(nodes);

    /* ----------- Create multiple paths ----------- */

    Ipv4AddressHelper ipv4;
    // --- 第一條鏈路 (10.1.1.0) ---
    PointToPointHelper p2p1;
    p2p1.SetDeviceAttribute("DataRate", StringValue("128Kbps"));
    p2p1.SetChannelAttribute("Delay", StringValue("5ms"));
    NetDeviceContainer dev1 = p2p1.Install(nodes);
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer i = ipv4.Assign(dev1);
    Ptr<RateErrorModel> em1 = CreateObject<RateErrorModel>();
    em1->SetRate(0.05);
    em1->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
    dev1.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em1));

    // --- 第二條鏈路 (10.1.2.0) ---
    PointToPointHelper p2p2;
    p2p2.SetDeviceAttribute("DataRate", StringValue("10Kbps"));
    p2p2.SetChannelAttribute("Delay", StringValue("2ms"));
    NetDeviceContainer dev2 = p2p2.Install(nodes);
    ipv4.SetBase("10.1.2.0", "255.255.255.0");
    ipv4.Assign(dev2);
    Ipv4InterfaceContainer i2 = ipv4.Assign(dev2); // second ip on this route
    Ptr<RateErrorModel> em2 = CreateObject<RateErrorModel>();
    em2->SetRate(0.01);
    em2->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
    dev2.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em2));

    // ---第三條鏈路(10.1.3.0)---
    PointToPointHelper p2p3;
    p2p3.SetDeviceAttribute("DataRate", StringValue("1Mbps"));
    p2p3.SetChannelAttribute("Delay", StringValue("10ms"));
    NetDeviceContainer dev3 = p2p3.Install(nodes);
    ipv4.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer i3 = ipv4.Assign(dev3);
    Ptr<RateErrorModel> em3 = CreateObject<RateErrorModel>();
    em3->SetRate(0.1);
    em3->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
    dev3.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em3));

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
    source.SetAttribute("SendSize", UintegerValue(200));

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
