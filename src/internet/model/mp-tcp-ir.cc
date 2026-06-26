#include "ns3/mp-tcp-ir.h"

#include "ns3/enum.h"

NS_LOG_COMPONENT_DEFINE("TcpOptionIR");

namespace ns3 {

    inline void set_bit8(uint8_t& flag, uint8_t offset) {
        (flag) |= (1U << (offset));
        return;
    }

    inline bool get_bit8(const uint8_t& flag, uint8_t offset) {
        return (1U & (flag >> offset));
    }

    inline void clear_bit8(uint8_t& flag, uint8_t offset) {
        flag &= ~(1U << (offset));
        return;
    }

    // inline std::string EncodingTypeToString(TcpOptionIR::EncodingType type) {
    //     switch (type) {
    //     case TcpOptionIR::XOR:
    //         return "XOR";
    //     case TcpOptionIR::InterleavedFEC:
    //         return "InterleavedFEC";
    //     case TcpOptionIR::ReedSolomon:
    //         return "Reed-Solomon";
    //     default:
    //         return "Unknown";
    //     }
    // }

    std::string TcpOptionIRv2::EncodingTypeToString(EncodingType type) {
        switch (type) {
        case TcpOptionIRv2::XOR:
            return "XOR";
        case TcpOptionIRv2::InterleavedFEC:
            return "InterleavedFEC";
        case TcpOptionIRv2::ReedSolomon:
            return "Reed-Solomon";
        default:
            return "Unknown";
        }
    }

    /*TypeId TcpOptionIR::GetTypeId() {
        static TypeId tid =
            TypeId("ns3::TcpOptionIR")
                .SetParent<TcpOption>()
                .SetGroupName("Internet")
                .AddConstructor<TcpOptionIR>()
                .AddAttribute(
                    "Encoding",
                    "Encoding type used for TCP-IR option.",
                    EnumValue(XOR),
                    MakeEnumAccessor<EncodingType>(&TcpOptionIR::encoding),
                    MakeEnumChecker<EncodingType>(XOR, "XOR", ReedSolomon, "Reed-Solomon"));

        return tid;
    }

    TcpOptionIR::TcpOptionIR()
        : syned(true),
          flag(),
          kind(INSTANT_RECOVERY), // Experimental option kind, replace if needed
          length(3),              // SYN format default: Kind + Length + Encoding
          encoding(XOR),
          range(0) {
    }

    TcpOptionIR::TcpOptionIR(bool isSyned)
        : syned(isSyned),
          flag(),
          kind(INSTANT_RECOVERY), // Experimental option kind, replace if needed
          length(3),              // SYN format default: Kind + Length + Encoding
          encoding(XOR),
          range(0) {
    }

    uint8_t TcpOptionIR::GetKind() const {
        return kind;
    }

    // uint32_t TcpOptionIR::GetSerializedSize() const {
    //     return length;
    // }

    void TcpOptionIR::Serialize(Buffer::Iterator start) const {
        Buffer::Iterator i = start;
        i.WriteU8(kind);
        auto l = static_cast<uint8_t>(GetSerializedSize());
        i.WriteU8(l);

        if (!this->syned) {
            i.WriteU8(static_cast<uint8_t>(encoding));
            return;
        }

        switch (this->flag) {
        case ENCODED:
            if (l == 7) {
                i.WriteHtonU32(range);
            } else {
                NS_ABORT_MSG("here should spec a range.");
            }
            break;
        default:
            NS_ABORT_MSG("not impl yet!");
            break;
        }
        return;
    }

    uint32_t TcpOptionIR::Deserialize(Buffer::Iterator start) {
        Buffer::Iterator i = start;

        kind = i.ReadU8();
        length = i.ReadU8();
        size_t real_size{2U};
        // this->flag=i.ReadU8(); // flags
        this->encoding = static_cast<EncodingType>(this->flag = i.ReadU8());
        if (length == 7) {
            i.ReadU8(); // flags
            range = i.ReadNtohU32();
            return 7;
        }
        return length;
    }

    uint32_t TcpOptionIR::GetSerializedSize() const {
        if (!this->syned) {
            return 3;
        } else if (range) {
            return 7;
        }
        return 3;
    }

    void TcpOptionIR::SetEncodingType(EncodingType encoding) {
        this->encoding = encoding;
        return;
    }

    uint8_t TcpOptionIR::GetFlag() const {
        return this->flag;
    }

    uint8_t TcpOptionIR::SetRecoveryStatus(bool status) { // true if recovery success, else false
        if (status) {                                     // succ
            set_bit8(this->flag, R_SUCCESS);
            clear_bit8(this->flag, R_FAIL);
        } else { // fail
            clear_bit8(this->flag, R_SUCCESS);
            set_bit8(this->flag, R_FAIL);
        }
        return this->flag;
    }

    uint8_t TcpOptionIR::SetCWR(bool enable) {
        if (enable) {
            set_bit8(this->flag, R_CWR);
        } else {
            clear_bit8(this->flag, R_CWR);
        }
        return this->flag;
    }

    uint8_t TcpOptionIR::SetEncoded(bool enable) {
        if (enable) {
            set_bit8(this->flag, ENCODED);
        } else {
            clear_bit8(this->flag, ENCODED);
        }
    }

    uint32_t TcpOptionIR::GetRange() const {
        return this->range;
    }

    void TcpOptionIR::SetRange(uint32_t range) {
        this->range = range;
        return;
    }

    TcpOptionIR::EncodingType TcpOptionIR::GetEncodingType() const {
        return this->encoding;
    }

    void TcpOptionIR::Print(std::ostream& os) {
        os << "TCP-IR Option"
           << " kind=" << +kind << " length=" << +length
           << " encoding=" << EncodingTypeToString(this->encoding) << " range=" << range;
    }\\*/

    TypeId TcpOptionIRv2::GetTypeId() {
        static TypeId tid =
            TypeId("TcpOptionIRv2")
                .SetParent<TcpOption>()
                .SetGroupName("Internet")
                .AddConstructor<TcpOptionIRv2>()
                .AddAttribute(
                    "Encoding",
                    "Encoding type used for TCP-IR option.",
                    EnumValue(XOR),
                    MakeEnumAccessor<EncodingType>(&TcpOptionIRv2::encoding),
                    MakeEnumChecker<EncodingType>(XOR, "XOR", ReedSolomon, "Reed-Solomon"));

        return tid;
    }

    TcpOptionIRv2::TcpOptionIRv2()
        : kind(INSTANT_RECOVERY),
          length(0),
          flag(0),
          stat(None),
          range(0),
          ecc_range(0) {
    }

    TcpOptionIRv2::TcpOptionIRv2(State stat)
        : kind(INSTANT_RECOVERY),
          length(0),
          flag(0),
          stat(stat),
          range(0),
          ecc_range(0) {
    }

    uint8_t TcpOptionIRv2::GetKind() const {
        return INSTANT_RECOVERY;
    }

    void TcpOptionIRv2::Serialize(Buffer::Iterator start) const {
        NS_LOG_FUNCTION(this);
        auto it = start;
        it.WriteU8(INSTANT_RECOVERY);
        auto l = this->GetSerializedSize();
        it.WriteU8(l);
        switch (stat) {
        case None:
        case Syned:
            it.WriteU8(0);
            it.WriteU8(static_cast<uint8_t>(encoding));
            break;
        case Received:
            it.WriteU8(1U);
            it.WriteU8(static_cast<uint8_t>(encoding));
            break;
        case Connect:
            it.WriteU8(flag);
            if (flag == ENCODED) {
                NS_ASSERT_MSG(!(ecc_range > range), "ecc_range CANNOT bigger than range.");
                it.WriteHtonU16(range);
                it.WriteHtonU16(ecc_range);
            }
            break;
        default:
            break;
        }
        return;
    }

    uint32_t TcpOptionIRv2::Deserialize(Buffer::Iterator start) {
        NS_LOG_FUNCTION(this);
        auto it = start;
        this->kind = it.ReadU8();
        size_t len = it.ReadU8();
        this->flag = it.ReadU8();
        this->length = 3;
        if (len == 4) {
            this->echo = get_bit8(flag, TCPIR_FLAG_E);
            this->encoding = static_cast<EncodingType>(it.ReadU8());
            this->length = 4;
        } else {
            len -= 3;
            if (this->flag == ENCODED) {
                this->stat = Connect;
                NS_ASSERT(this->length == 3);
                NS_ASSERT(len == 4); // 16bit range+16bit ecc_range
                this->range = it.ReadNtohU16();
                this->ecc_range = it.ReadNtohU16();
                NS_ASSERT_MSG(ecc_range <= range,
                              "ecc_range should not bigger than range, ingnored.");
                this->length += 4;
            } else {
                NS_ABORT_MSG("not implement yet!");
                this->length = 0;
            }
        }
        NS_LOG_DEBUG("TcpOptionIRv2::Deserialize -> length: " << +this->length);
        NS_ASSERT_MSG(this->length == this->GetSerializedSize(),
                      "this->length: " << +this->length
                                       << "serializedsize: " << this->GetSerializedSize());
        return this->length;
    }

    uint32_t TcpOptionIRv2::GetSerializedSize() const {
        uint32_t size;
        switch (this->stat) {
        case None:
        case Syned:
        case Received:
            size = 4;
            break;
        case Connect:
            size = 3;
            if (this->flag == ENCODED) {
                size += 4;
            }
            break;
        default:
            NS_LOG_WARN("unknow state, return 0 as size.");
            size = 0;
        }
        return size;
    }

    void TcpOptionIRv2::SetEncodingType(EncodingType encoding) {
        this->encoding = encoding;
        return;
    }

    TcpOptionIRv2::EncodingType TcpOptionIRv2::GetEncodingType() const {
        return this->encoding;
    }

    uint8_t TcpOptionIRv2::GetFlag() const {
        return this->flag;
    }

    uint8_t TcpOptionIRv2::SetRecoveryStatus(bool status) { // true if recovery success, else false
        if (status) {                                       // succ
            set_bit8(this->flag, R_SUCCESS);
            clear_bit8(this->flag, R_FAIL);
        } else { // fail
            clear_bit8(this->flag, R_SUCCESS);
            set_bit8(this->flag, R_FAIL);
        }
        return this->flag;
    }

    void TcpOptionIRv2::SetEncoded(bool enable) {
        if (enable) {
            this->flag = ENCODED;
        } else {
            this->flag &= ~ENCODED;
        }
    }

    uint32_t TcpOptionIRv2::GetRange() const {
        return this->range;
    }

    void TcpOptionIRv2::SetRange(uint32_t range) {
        this->range = range;
        return;
    }

    void TcpOptionIRv2::SetEccRange(uint16_t range) {
        this->ecc_range = range;
        return;
    }

    uint16_t TcpOptionIRv2::GetEccRange() const {
        return this->ecc_range;
    }

    bool TcpOptionIRv2::IsEcho() const {
        return this->echo;
    }

    void TcpOptionIRv2::SetEcho(bool enable) {
        this->echo = enable;
        return;
    }

    void TcpOptionIRv2::Print(std::ostream& os) const {
        os << "TCP-IR Option"
           << " kind=" << +kind << " length=" << +GetSerializedSize()
           << " encoding=" << this->EncodingTypeToString(this->encoding) << " range=" << range;
    }

} // namespace ns3
