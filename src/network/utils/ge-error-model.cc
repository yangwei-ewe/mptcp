#include "ge-error-model.h"

#include "ns3/double.h"
#include "ns3/log.h"
#include "ns3/packet.h"
#include "ns3/pointer.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"

#include <algorithm>

namespace ns3 {

    NS_LOG_COMPONENT_DEFINE("GEErrorModel");
    NS_OBJECT_ENSURE_REGISTERED(GEErrorModel);

    struct GEParams {
        double p_good_bad;
        double p_bad_good;
    };

    // 512 byte packet 參數表 (7 種 PLR 等級: 1%, 5%, 10%, 20%, 30%, 40%, 50%)
    static const GEParams TBL_512[7] = {{0.00116, 0.11507},
                                        {0.00585, 0.11124},
                                        {0.01151, 0.10363},
                                        {0.02330, 0.09320},
                                        {0.03554, 0.08292},
                                        {0.05047, 0.07570},
                                        {0.06604, 0.06604}};

    // 1024 byte packet 參數表
    static const GEParams TBL_1024[7] = {{0.00232, 0.22989},
                                         {0.01172, 0.22272},
                                         {0.02310, 0.20790},
                                         {0.04664, 0.18657},
                                         {0.07119, 0.16611},
                                         {0.10117, 0.15175},
                                         {0.13193, 0.13193}};

    // 1400 byte packet 參數表
    static const GEParams TBL_1400[7] = {{0.00319, 0.31546},
                                         {0.01600, 0.30395},
                                         {0.03139, 0.28249},
                                         {0.06427, 0.25707},
                                         {0.09718, 0.22676},
                                         {0.13803, 0.20704},
                                         {0.17986, 0.17986}};

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
                              "Packet size in bytes for table lookup",
                              UintegerValue(1024),
                              MakeUintegerAccessor(&GEErrorModel::SetPacketSize,
                                                   &GEErrorModel::GetPacketSize),
                              MakeUintegerChecker<uint32_t>())
                .AddAttribute("RanVar",
                              "The decision variable attached to this error model.",
                              StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1.0]"),
                              MakePointerAccessor(&GEErrorModel::m_ranvar),
                              MakePointerChecker<RandomVariableStream>());
        ;
        return tid;
    }

    GEErrorModel::GEErrorModel()
        : m_plr(0.0),
          m_packetSize(1024),
          m_currentState(true) {
    }

    GEErrorModel::~GEErrorModel() {
    }

    void GEErrorModel::SetPlr(double plr) {
        this->m_plr = std::clamp(plr, 0.0, 1.0);
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

        // 根據封包大小選擇對應的 constexpr 陣列指標
        const GEParams* tbl = nullptr;
        if (m_packetSize <= 768) {
            tbl = TBL_512;
        } else if (m_packetSize <= 1212) {
            tbl = TBL_1024;
        } else {
            tbl = TBL_1400;
        }

        // 查表索引對應
        int p_loss = static_cast<int>(m_plr * 100.0);
        int idx{-1};
        if (p_loss <= 0) {
            idx = -1;
        } else if (p_loss >= 1 && p_loss <= 4) {
            idx = 0;
        } else if (p_loss >= 5 && p_loss <= 9) {
            idx = 1;
        } else if (p_loss >= 10 && p_loss <= 19) {
            idx = 2;
        } else if (p_loss >= 20 && p_loss <= 29) {
            idx = 3;
        } else if (p_loss >= 30 && p_loss <= 39) {
            idx = 4;
        } else if (p_loss >= 40 && p_loss <= 49) {
            idx = 5;
        } else if (p_loss >= 50 && p_loss <= 60) {
            idx = 6;
        } else {
            idx = 2; // fallback: 10%
        }
        auto& [p_good_bad, p_bad_good] = tbl[idx];
        double random_num = m_ranvar->GetValue();

        if (m_currentState) { // 目前為 Good state
            if (random_num < p_good_bad) {
                m_currentState = false; // 轉移到 Bad
            }
        } else { // 目前為 Bad state
            if (random_num < p_bad_good) {
                m_currentState = true; // 轉移到 Good
            }
        }

        // 若當前狀態為 Bad 則回傳 true (代表封包損毀/遺失)
        return !m_currentState;
    }

} // namespace ns3
