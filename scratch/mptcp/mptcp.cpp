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
#include "ns3/flow-monitor-module.h"
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
    // LogComponentEnable("ReedSolomonFec", LOG_LEVEL_ALL);

    // LogComponentEnable("MpTcpTypeDefs", LOG_LEVEL_ALL);
    // LogComponentEnable("fec", LOG_LEVEL_ALL);
    // LogComponentEnable("TcpOptionIR", LOG_LEVEL_ALL);

    // LogComponentEnable("Ipv4EndPointDemux", LOG_LEVEL_ALL);
    // LogComponentEnable("TcpL4Protocol", LOG_LEVEL_ALL);
    // LogComponentEnable("TcpSocketBase", LOG_LEVEL_ALL);
    // LogComponentEnable("MpTcpSubflow", LOG_LEVEL_ALL);

    /* ----------- TCP / MPTCP configuration ----------- */

    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(1024)); // relate to MSS
    Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(0));
    Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(32768)); // 32k
    Config::SetDefault("ns3::MpTcpSocketBase::FecEnable", BooleanValue(true));
    Config::SetDefault("ns3::MpTcpSocketBase::FecAlgorithm", EnumValue(ReedSolomon));
    Config::SetDefault("ns3::MpTcpSocketBase::FecBlockSize", UintegerValue(6));

    Config::SetDefault("ns3::TcpL4Protocol::SocketType", TypeIdValue(MpTcpSocketBase::GetTypeId()));

    Config::SetDefault("ns3::MpTcpSocketBase::MaxSubflows", UintegerValue(8));
    Config::SetDefault("ns3::MpTcpSocketBase::CheckAlgorithm", EnumValue(HMAC_MURMUR3));
    Config::SetDefault("ns3::RateErrorModel::ErrorUnit",
                       EnumValue(RateErrorModel::ERROR_UNIT_PACKET));
    // Config::SetDefault("ns3::MpTcpPacketSink::ExportFileName", StringValue("rx_buf.txt"));
    // Config::SetDefault("ns3::MpTcpBulkSendApplication::MaxBytes", UintegerValue(0));

    auto rand = 1783961193; // 3rd 3whs dropped
    // auto rand = 1785420965; // super low thoughput
    // auto rand = time(NULL);
    std::cout << "Random number: " << rand << std::endl;
    RngSeedManager::SetSeed(rand);

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
    p2p1.SetDeviceAttribute("DataRate", StringValue("1Mbps"));
    p2p1.SetChannelAttribute("Delay", StringValue("10ms"));
    // p2p1.EnableAsciiAll("p2p-trace");
    NetDeviceContainer dev1 = p2p1.Install(nodes);
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer i = ipv4.Assign(dev1);
    Ptr<RateErrorModel> em1 = CreateObject<RateErrorModel>();
    em1->SetRate(0.10);
    dev1.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em1));

    // --- 第二條鏈路 (10.1.2.0) ---
    PointToPointHelper p2p2;
    p2p2.SetDeviceAttribute("DataRate", StringValue("100Kbps"));
    p2p2.SetChannelAttribute("Delay", StringValue("2ms"));
    NetDeviceContainer dev2 = p2p2.Install(nodes);
    ipv4.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer i2 = ipv4.Assign(dev2); // second ip on this route
    Ptr<RateErrorModel> em2 = CreateObject<RateErrorModel>();
    em2->SetRate(0.10);
    dev2.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em2));

    // ---第三條鏈路(10.1.3.0)---
    PointToPointHelper p2p3;
    p2p3.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p3.SetChannelAttribute("Delay", StringValue("25ms"));
    NetDeviceContainer dev3 = p2p3.Install(nodes);
    ipv4.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer i3 = ipv4.Assign(dev3);
    Ptr<RateErrorModel> em3 = CreateObject<RateErrorModel>();
    em3->SetRate(0.10);
    dev3.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em3));

    // --- 第四條鏈路 (10.1.4.0) ---
    PointToPointHelper p2p4;
    p2p4.SetDeviceAttribute("DataRate", StringValue("1Mbps"));
    p2p4.SetChannelAttribute("Delay", StringValue("10ms"));
    NetDeviceContainer dev4 = p2p4.Install(nodes);
    ipv4.SetBase("10.1.4.0", "255.255.255.0");
    ipv4.Assign(dev4);
    Ipv4InterfaceContainer i4 = ipv4.Assign(dev4); // second ip on this route
    Ptr<RateErrorModel> em4 = CreateObject<RateErrorModel>();
    em4->SetRate(0.10);
    dev4.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em4));

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
    source.SetAttribute("SendSize", UintegerValue(1500));

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    ApplicationContainer sourceApps = source.Install(nodes.Get(0));
    sourceApps.Start(Seconds(0.0));
    sourceApps.Stop(Seconds(20.0));

    /* ----------- Run simulation ----------- */

    NS_LOG_INFO("Run Simulation");
    Simulator::Stop(Seconds(20.0));
    Simulator::Run();
    // monitor->CheckForLostPackets();

    // 取得分類器，用來把 Flow ID 轉回我們看得懂的 IP 和 Port
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();

    std::cout << "\n=== MPTCP Subflow 流量統計結果 ===\n";

    for (const auto& pair : stats) {
        // 透過 FlowId 找出這條流量的 5-Tuple 資訊
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(pair.first);
        // 排除掉不重要的流量（例如點對點的路由協定流量，只看 TCP）
        if (t.protocol == 6) // 6 代表 TCP
        {
            std::cout << "Flow ID: " << pair.first << "\n";
            std::cout << "  路徑: " << t.sourceAddress << ":" << t.sourcePort << " -> "
                      << t.destinationAddress << ":" << t.destinationPort << "\n";
            std::cout << setw(6) << "  傳送數據量 (Tx Bytes): " << (pair.second.txBytes) / 1e3
                      << " Kbytes\n";
            std::cout << setw(6) << "  接收數據量 (Rx Bytes): " << (pair.second.rxBytes) / 1e3
                      << " Kbytes\n";
            std::cout << "  packets dropped: " << pair.second.packetsDropped.size() << " pkts\n";
            std::cout << setw(6) << "  吞吐量 (Throughput): "
                      << (pair.second.rxBytes * 8.0 /
                          (pair.second.timeLastRxPacket.GetSeconds() -
                           pair.second.timeFirstTxPacket.GetSeconds())) /
                             1024 / 1024
                      << " Mbps\n";
            std::cout << "-----------------------------------------------\n";
        }
    }

    // 5. 選擇性：你也可以直接匯出一份 XML 檔案，用 Python 腳本去畫圖
    monitor->SerializeToXmlFile("mptcp-flowmon-results.xml", true, true);
    Simulator::Destroy();
    NS_LOG_INFO("Simulation finished");

    return 0;
}
