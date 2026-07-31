#ifndef FEC_HELPER_H
#define FEC_HELPER_H
#include "ns3/fec.h"
#include "ns3/packet.h"
#include "ns3/reed_solomon.h"

namespace ns3 {
    class MpTcpFecFactory {
      public:
        std::shared_ptr<MpTcpFec> Create(FecAlgorithm algo) {
            switch (algo) {
            case FecAlgorithm::XOR:
                return std::make_shared<XorFec>();
            case FecAlgorithm::InterVealed_XOR:
            case FecAlgorithm::ReedSolomon:
                return std::make_shared<ReedSolomonFec>();
                // NS_ABORT_MSG("Not Impl yet.");
                // break;
            // return std::make_shared<ReedSolomonFec>();
            default:
                break;
            }
            NS_ABORT_MSG("?");
            return nullptr;
        }
    };
} // namespace ns3

#endif // FEC_HELPER_H
