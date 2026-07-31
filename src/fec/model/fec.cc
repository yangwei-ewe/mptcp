#include "ns3/fec.h"

#include <cmath>
#include <iomanip>
#include <sstream>

NS_LOG_COMPONENT_DEFINE("fec");

namespace ns3 {
    std::vector<Buffer> MpTcpFec::Encode(const std::vector<Buffer>& symbol, double fec_ratio) {
        NS_LOG_FUNCTION(this << symbol.size() << static_cast<uint32_t>(fec_ratio * 100) << "%");
        size_t max_symb_length{};
        NS_ASSERT(symbol.size());
        for (const auto& buf : symbol) {
            max_symb_length = std::max(max_symb_length, static_cast<size_t>(buf.GetSize()));
        }
        size_t total_len =
            std::min(rint((fec_ratio + 1.0) * symbol.size()),
                     pow(max_symb_length * 8,
                         2)); //(num_symb+repair_symb) must smaller than 2^(bitlen(symb_len))
        NS_ASSERT_MSG(total_len > symbol.size(),
                      "total package num must bigger then orig. symb len! total: "
                          << total_len << " symb.size(): " << symbol.size());
        size_t ecc_len = total_len - symbol.size();
        NS_LOG_DEBUG("MpTcpFec::Encode -> ecc_len: " << ecc_len);
        std::vector<SymbBlock> _symb(symbol.size());
        for (size_t i{}; i < _symb.size(); i++) {
            uint8_t* it = _symb[i].symb = new uint8_t[max_symb_length];
            _symb[i].symb_len = max_symb_length;
            memset(it, 0, max_symb_length);
            symbol[i].CopyData(it, symbol[i].GetSize());
        }
        auto ecc_pkts = EncodeImpl(_symb, ecc_len);

        std::vector<Buffer> ecc_packets(ecc_len);
        for (size_t i{0}; i < ecc_len; i++) {
            ecc_packets[i].AddAtEnd(max_symb_length);
            auto it = ecc_packets[i].Begin();
            it.Write(ecc_pkts[i].symb, ecc_pkts[i].symb_len);
        }

        // uint8_t peek[50];
        // ecc_packets[0].CopyData(peek, sizeof(peek) - 1);
        // peek[49] = '\0';
        // std::stringstream ss;
        // for (auto ch : peek) {
        //     ss << std::setw(3) << std::setfill(' ') << +ch << " ";
        // }
        // NS_LOG_DEBUG("MpTcpFec::Encode -> peek data: " << ss.str());
        // // ecc_pkts[0].CopyData(peek, sizeof(peek) - 1);
        // memcpy(peek, ecc_pkts[0].symb, sizeof(peek) - 1);
        // peek[49] = '\0';
        // ss.str("");
        // for (auto ch : peek) {
        //     ss << std::setw(3) << std::setfill(' ') << +ch << " ";
        // }
        // NS_LOG_DEBUG("MpTcpFec::Encode -> peek data: " << ss.str());
        // dont forget delete
        for (auto it : _symb) {
            delete[] it.symb;
            it.symb = nullptr;
            it.symb_len = 0;
        }
        for (auto it : ecc_pkts) {
            delete[] it.symb;
            it.symb = nullptr;
            it.symb_len = 0;
        }
        return ecc_packets;
    }

    std::vector<Buffer> MpTcpFec::Decode(const std::vector<std::pair<int, Buffer>>& symbol,
                                         size_t ecc_len,
                                         size_t dest_pack_num) {
        NS_LOG_FUNCTION(this << dest_pack_num);
        size_t symb_length = symbol[0].second.GetSize();
        int missing_idx{0};
        for (auto& it : symbol) {
            NS_LOG_DEBUG("id: " << it.first);
            if (it.first != missing_idx) {
                break;
            }
            missing_idx++;
        }
        if (missing_idx >= static_cast<int>(dest_pack_num)) {
            std::vector<Buffer> rtn;
            rtn.reserve(dest_pack_num);
            for (size_t i{0}; i < dest_pack_num; i++) {
                // NS_ASSERT(symbol.find(dest_pack_num) != symbol.end());
                rtn.push_back(symbol[static_cast<int>(i)].second);
            }
            return rtn;
        }
        std::vector<std::pair<int, SymbBlock>> _symb(symbol.size());

        for (size_t i{}; i < _symb.size(); i++) {
            uint8_t* it = _symb[i].second.symb = new uint8_t[symb_length];
            _symb[i].first = symbol[i].first;
            _symb[i].second.symb_len = symb_length;
            memset(it, 0, symb_length);
            NS_ASSERT_MSG(symb_length == symbol[i].second.GetSize(),
                          "symb_length(" << symb_length
                                         << ") is not Eq. to symbol[i].second.GetSize()("
                                         << symbol[i].second.GetSize() << ")");
            symbol[i].second.CopyData(it, symbol[i].second.GetSize());
        }
        auto dest_pkts = this->DecodeImpl(_symb, ecc_len, dest_pack_num);
        std::vector<Buffer> dest_packs(dest_pack_num);
        // std::stringstream ss;
        for (size_t i{}; i < dest_pack_num; i++) {
            dest_packs[i].AddAtEnd(dest_pkts[i].symb_len);
            auto it = dest_packs[i].Begin();
            it.Write(dest_pkts[i].symb, dest_pkts[i].symb_len);
            // uint8_t peek[50];
            // dest_packs[i].CopyData(peek, sizeof(peek));
            // peek[50] = '\0';
            // NS_LOG_DEBUG("MpTcpFec::Decode -> decode: [" << i << "] msg: " << peek);
        }

        // NS_LOG_DEBUG("DSNMapping::Received -> received data: " << ss.str());
        for (auto& blk : _symb) {
            delete[] blk.second.symb;
            // blk.second.symb = nullptr;
            // blk.second.symb_len = 0;
            blk.second = {nullptr, 0};
        }
        for (auto& it : dest_pkts) {
            delete[] it.symb;
            it.symb = nullptr;
            it.symb_len = 0;
        }
        return dest_packs;
    }

    std::vector<Buffer> MpTcpFec::Decode(const std::map<int, Buffer>& symbol,
                                         size_t ecc_len,
                                         size_t dest_pack_num) {
        NS_LOG_FUNCTION(this << dest_pack_num);

        if (symbol.empty()) {
            return {};
        }

        int missing_idx{0};
        for (auto& it : symbol) {
            NS_LOG_DEBUG("id: " << it.first);
            if (it.first != missing_idx) {
                break;
            }
            missing_idx++;
        }
        NS_LOG_DEBUG("?");
        if (missing_idx >= static_cast<int>(dest_pack_num)) {
            std::vector<Buffer> rtn;
            rtn.reserve(dest_pack_num);
            for (size_t i{0}; i < dest_pack_num; i++) {
                // NS_ASSERT(symbol.find(dest_pack_num) != symbol.end());
                rtn.push_back(symbol.at(static_cast<int>(i)));
            }
            return rtn;
        }

        size_t symb_length = symbol.begin()->second.GetSize();

        std::vector<std::pair<int, SymbBlock>> _symb;
        _symb.reserve(symbol.size());

        for (const auto& kv : symbol) {
            int id = kv.first;
            const Buffer& buf = kv.second;

            SymbBlock block;
            block.symb_len = symb_length;
            block.symb = new uint8_t[symb_length];
            memset(block.symb, 0, symb_length);

            size_t copy_size = std::min(symb_length, (size_t)buf.GetSize());
            buf.CopyData(block.symb, copy_size);

            _symb.push_back({id, block});
        }

        auto dest_pkts = this->DecodeImpl(_symb, ecc_len, dest_pack_num);

        std::vector<Buffer> dest_packs(dest_pack_num);
        for (size_t i = 0; i < dest_pack_num; i++) {
            if (i < _symb.size()) {
                dest_packs[i].AddAtEnd(_symb[i].second.symb_len);
                auto it = dest_packs[i].Begin();
                it.Write(_symb[i].second.symb, _symb[i].second.symb_len);
            }
        }

        // 4. 釋放動態配置的記憶體
        for (auto& blk : _symb) { // 修正：必須使用引用 & 才能真正修改 blk 裡面的值
            delete[] blk.second.symb;
            blk.second = {nullptr, 0};
        }

        return dest_packs;
    }

    void MpTcpFec::SetRatioRange(double max, double min) {
        this->max_fec_rate = max;
        this->min_fec_rate = min;
        return;
    }

    XorFec::XorFec() {
        // Dummy constructor, gcc-generated one crashes program
    }

    std::pair<uint8_t, double> XorFec::Update(size_t rtt) {
        NS_LOG_FUNCTION(this << rtt);
        return {5, 0.2};
    }

    std::vector<SymbBlock> XorFec::EncodeImpl(const std::vector<SymbBlock>& symb, size_t ecc_len) {
        NS_LOG_FUNCTION(this << ecc_len);
        NS_LOG_DEBUG("XorFec::EncodeImpl -> symb[0].symb_len " << symb[0].symb_len);
        if (ecc_len > 1) {
            NS_LOG_DEBUG("XorFec only provide n+1 redundant, ignore assigned ecc_len.");
        }
        std::vector<SymbBlock> ecc_pack(1);
        auto symb_len = symb[0].symb_len;
        ecc_pack[0] = {.symb = new uint8_t[symb_len], .symb_len = symb_len};
        memset(ecc_pack[0].symb, 0, symb_len);
        for (const auto& it : symb) {
            for (size_t i = 0; i < symb_len; i++) {
                ecc_pack[0].symb[i] ^= it.symb[i];
            }
        }
        // uint8_t peek[50];
        // memcpy(peek, ecc_pack[0].symb, sizeof(peek) - 1);
        // peek[49] = '\0';
        // std::stringstream ss;
        // for (auto ch : peek) {
        //     ss << std::setw(3) << std::setfill(' ') << +ch << " ";
        // }
        // NS_LOG_DEBUG("XorFec::EncodeImpl -> peek data: " << ss.str());
        return ecc_pack;
    }

    std::vector<SymbBlock> XorFec::DecodeImpl(const std::vector<std::pair<int, SymbBlock>>& symbol,
                                              size_t ecc_len,
                                              size_t pack_num) {
        NS_LOG_FUNCTION(this << pack_num);
        // for(size_t i{};i<symb_len)
        if (abs(pack_num - symbol.rbegin()->first) >
            1) { // missing more than one packet (which xorfec cannot handle it)
            NS_LOG_WARN("XorFec::DecodeImpl -> missing more than one packet, return");
            return {};
        }
        if (symbol.size() > pack_num) {
            NS_LOG_WARN("XorFec::DecodeImpl -> received more than pack_num, return");
            return {};
        }
        int missing_idx{0};
        size_t symb_len = symbol[0].second.symb_len;
        for (auto& it : symbol) {
            NS_LOG_DEBUG(it.first);
            if (it.first != missing_idx) {
                break;
            }
            missing_idx++;
        }
        NS_LOG_DEBUG("XorFec::DecodeImpl -> missing pkt idx: " << missing_idx);

        std::vector<SymbBlock> decode_pkts(pack_num);
        for (size_t i{0}; i < pack_num; i++) {
            if (symbol[i].first == missing_idx) {
                continue;
            }
            memcpy(decode_pkts[i].symb, symbol[i].second.symb, symb_len);
        }
        if (missing_idx >= static_cast<int>(pack_num)) {
            return decode_pkts;
        }
        uint8_t* repair = new uint8_t[symb_len];
        memset(repair, 0, symb_len);
        for (const auto& it : symbol) {
            // uint8_t peek[20];
            // memcpy(peek, it.second.symb, sizeof(peek));
            // peek[20] = '\0';
            // NS_LOG_DEBUG("XorFec::DecodeImpl -> xor data: " << peek);
            for (size_t i = 0; i < it.second.symb_len; i++) {
                repair[i] ^= it.second.symb[i];
            }
        }

        // uint8_t peek[20];
        // memcpy(peek, repair, sizeof(peek));
        // NS_LOG_DEBUG("XorFec::DecodeImpl -> after xor: " << peek);
        decode_pkts[missing_idx] = {.symb = repair, .symb_len = symb_len};
        return decode_pkts;
    }
} // namespace ns3
