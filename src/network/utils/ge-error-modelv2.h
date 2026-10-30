#include "ge-error-model.h"

#include "ns3/double.h"
#include "ns3/log.h"
#include "ns3/packet.h"
#include "ns3/pointer.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"

#include <algorithm>
#include <cmath>

namespace ns3 {

    NS_LOG_COMPONENT_DEFINE("GEErrorModel");
    NS_OBJECT_ENSURE_REGISTERED(GEErrorModel);

    TypeId GEErrorModel::GetTypeId(void) {
        static TypeId tid =
            TypeId("ns3::GEErrorModel")
                .SetParent<ErrorModel>()
                .SetGroupName("Network")
                .AddConstructor<GEErrorModel>()
                .AddAttribute("Plr",
                              "Target Packet Loss Rate (PLR)",
                              DoubleValue(0.0),
                              MakeDoubleAccessor(&GEErrorModel::SetPlr, &GEErrorModel::GetPlr),
                              MakeDoubleChecker<double>(0.0, 1.0))
                .AddAttribute("PacketSize",
                              "Packet size in bytes",
                              UintegerValue(1024),
                              MakeUintegerAccessor(&GEErrorModel::SetPacketSize,
                                                   &GEErrorModel::GetPacketSize),
                              MakeUintegerChecker<uint32_t>())
                .AddAttribute("AverageBurstLength",
                              "Average error burst length (in packets)",
                              DoubleValue(5.0),
                              MakeDoubleAccessor(&GEErrorModel::SetAverageBurstLength,
                                                 &GEErrorModel::GetAverageBurstLength),
                              MakeDoubleChecker<double>(1.0, 1000.0))
                .AddAttribute("RanVar",
                              "The decision variable attached to this error model.",
                              StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1.0]"),
                              MakePointerAccessor(&GEErrorModel::m_ranvar),
                              MakePointerChecker<RandomVariableStream>());
        return tid;
    }

    GEErrorModel::GEErrorModel()
        : m_plr(0.0),
          m_packetSize(1024),
          m_avgBurstLength(5.0),
          m_currentState(true) {
    }

    GEErrorModel::~GEErrorModel() {
    }

    void GEErrorModel::SetPlr(double plr) {
        m_plr = std::clamp(plr, 0.0, 1.0);
    }

    double GEErrorModel::GetPlr(void) const {
        return m_plr;
    }

    void GEErrorModel::SetPacketSize(uint32_t packetSize) {
        m_packetSize = packetSize;
    }

    uint32_t GEErrorModel::GetPacketSize(void) const {
        return m_packetSize;
    }

    void GEErrorModel::SetAverageBurstLength(double burstLength) {
        m_avgBurstLength = std::max(1.0, burstLength);
    }

    double GEErrorModel::GetAverageBurstLength(void) const {
        return m_avgBurstLength;
    }

    bool GEErrorModel::GetCurrentState(void) const {
        return m_currentState;
    }

    void GEErrorModel::Reset(void) {
        DoReset();
    }

    void GEErrorModel::DoReset(void) {
        m_currentState = true;
    }

    bool GEErrorModel::DoCorrupt(Ptr<Packet> p) {
        NS_LOG_FUNCTION(this << p);
        if (m_plr == 0.0) {
            return false;
        }
        if (m_plr >= 1.0) {
            return true; // 遺失率 100%
        }

        // 根據 Gilbert-Elliott 模型公式動態計算轉移機率
        // q: 從 Bad 轉回 Good 的機率 (1 / 平均叢發長度)
        double q = 1.0 / m_avgBurstLength;
        // p: 從 Good 轉到 Bad 的機率
        double p = (m_plr / (1.0 - m_plr)) * q;

        // 限制 p 在合法機率範圍內 [0.0, 1.0]
        p = std::clamp(p, 0.0, 1.0);

        double random_num = m_ranvar->GetValue();

        if (m_currentState) { // 目前為 Good state
            if (random_num < p) {
                m_currentState = false; // 轉移到 Bad state
            }
        } else { // 目前為 Bad state
            if (random_num < q) {
                m_currentState = true; // 轉移到 Good state
            }
        }

        // 若當前狀態為 Bad 則回傳 true (代表封包損毀/遺失)
        return !m_currentState;
    }

} // namespace ns3
