#include "mp-tcp-fec.h"
NS_LOG_COMPONENT_DEFINE("MpTcpFec");

namespace ns3 {
    std::shared_ptr<MpTcpFec> MpTcpFecFactory::Create(FecAlogrithm fec) {
        switch (fec) {
        case XOR:
            return std::make_shared<XorFec>();
        case RaptorCode:
            return std::make_shared<RaptorCodeFec>();
        default:
            NS_ABORT_MSG("MpTcpFecFactory::Create(): invalid FEC algorithm!");
            return nullptr;
        }
    }
} // namespace ns3
