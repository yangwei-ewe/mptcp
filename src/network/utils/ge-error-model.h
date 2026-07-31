#ifndef GE_ERROR_MODEL_H
#define GE_ERROR_MODEL_H

#include "ns3/error-model.h"

#include <random>

namespace ns3 {

    class Packet;

    /**
     * \brief Gilbert-Elliott 狀態通道錯誤模型 (使用 std::mt19937 與 constexpr 查表)
     */
    class GEErrorModel : public ErrorModel {
      public:
        static TypeId GetTypeId(void);

        GEErrorModel();
        virtual ~GEErrorModel();

        void SetPlr(double plr);
        double GetPlr(void) const;

        void SetPacketSize(uint32_t packetSize);
        uint32_t GetPacketSize(void) const;

        bool GetCurrentState(void) const;
        void Reset(void);

      protected:
        bool DoCorrupt(Ptr<Packet> p) override;
        void DoReset(void) override;

      private:
        double m_plr;          ///< 目標封包遺失率
        uint32_t m_packetSize; ///< 封包大小 (bytes)
        bool m_currentState;   ///< 當前狀態 (true = Good, false = Bad)

        Ptr<RandomVariableStream> m_ranvar; //!< rng stream
        std::uniform_real_distribution<double> m_dist;
    };

} // namespace ns3

#endif // GE_ERROR_MODEL_H
