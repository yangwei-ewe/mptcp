#ifndef FEC_H
#define FEC_H
#include "ns3/packet.h"

#include <map>

namespace ns3 {
    enum FecAlgorithm : uint8_t {
        None = 0, // to Algiment to FecAlgorithm
        XOR,
        InterVealed_XOR,
        ReedSolomon
    };

    struct SymbBlock {
        uint8_t* symb;
        size_t symb_len;
    };

    class MpTcpFec {
      public:
        // MpTcpFec();
        ~MpTcpFec() = default;
        /**
         * @brief to encode source packet into encoded symbol.
         *
         * @param packet_list source symbol
         * @param fec_ratio rate of redundant in double
         * @return the list of redundant packet
         */
        virtual std::vector<Buffer> Encode(const std::vector<Buffer>& packet_list,
                                           double fec_ratio);
        /**
         * @brief to decode the encoded packet
         *
         * @param symbols list of encoded packet received
         * @param dest_pack_num number of source packet
         * @param idx the revalent sequence number of received packet
         * @return std::vector<Buffer>
         */
        virtual std::vector<Buffer> Decode(const std::vector<std::pair<int, Buffer>>& symbols,
                                           size_t ecc_len,
                                           size_t dest_pack_num);
        virtual std::vector<Buffer> Decode(const std::map<int, Buffer>& symbol,
                                           size_t ecc_len,
                                           size_t dest_pack_num);

        // virtual bool IsDecodeAble(const std::vector<std::pair<int, Buffer>>& symbols,
        //                                    size_t dest_pack_num);
        /**
         * @brief to update the FEC parameters according to the network status, e.g. RTT, loss rate,
         * etc.
         *
         * @param rtt
         * @return pair<block_size:uint8_t, fec_ratio:double>
         */
        virtual std::pair<uint8_t, double> Update(size_t rtt) = 0; // in ms

        virtual void SetRatioRange(double max, double min);

      protected:
        double min_fec_rate;
        double max_fec_rate;
        double fec_ratio;   // r
        uint8_t block_size; // k

        /**
         * @brief
         *
         * @param symb
         * @param ecc_len
         * @return std::vector<SymbBlock>
         */
        virtual std::vector<SymbBlock> EncodeImpl(const std::vector<SymbBlock>& symb,
                                                  size_t ecc_len) = 0;
        /**
         * @brief
         *
         * @param symbol
         * @param ecc_len
         * @param pack_num
         * @return std::vector<SymbBlock>
         */
        virtual std::vector<SymbBlock> DecodeImpl(
            const std::vector<std::pair<int, SymbBlock>>& symbol,
            size_t ecc_len,
            size_t pack_num) = 0;
        // virtual std::vector<SymbBlock> DecodeImpl(const std::map<int, SymbBlock>& symbol,
        //                                           size_t pack_num) = 0;
    };

    class XorFec : public MpTcpFec {
      public:
        XorFec();
        ~XorFec() = default;

        std::pair<uint8_t, double> Update(size_t rtt) override;

      protected:
        std::vector<SymbBlock> EncodeImpl(const std::vector<SymbBlock>& symb,
                                          size_t ecc_len) override;
        std::vector<SymbBlock> DecodeImpl(const std::vector<std::pair<int, SymbBlock>>& symbol,
                                          size_t ecc_len,
                                          size_t pack_num) override;
    };
} // namespace ns3

#endif // FEC_H
