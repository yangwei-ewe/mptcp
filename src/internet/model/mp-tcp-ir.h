#ifndef TCP_INSTENT_RECOVERY_H
#define TCP_INSTENT_RECOVERY_H

#include "ns3/buffer.h"
#include "ns3/object.h"
#include "ns3/tcp-option.h"

//                              1                   2
//          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
//        +---------------+---------------+---------------+
//        |   Kind = TBD  |   Length = 1  | Encoding Type |
//        +---------------+---------------+---------------+
//      Figure 2: TCP-IR Option format for packets with SYN flag set

//  During the initial handshake (for packets with the SYN flag set), the
//  option has the format shown in Figure 2.  It contains the following
//  fields:
//  Kind (8 bits)
//    This MUST be set to the option number for TCP-IR to be determined
//    by IANA.
//  Length (8 bits)
//    This MUST be set to the length of the TCP option in octets; its
//    value MUST be 1.
//  Encoding Type (8 bits)
//    This SHOULD be set to a value corresponding to a supported encoding
//    type (see Section 3.3).

//                         1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +---------------+---------------+---------------+---------------
//  |   Kind = TBD  |   Length      |   Flags       |
//  +---------------+---------------+---------------+---------------
//      Range (optional)            |
//  --------------------------------+
//  Figure 3: TCP-IR Option format (except for packets with SYN flag set)
//  Length (8 bits)
//    This MUST be set to the length of the TCP option in octets; its
//    value MUST be 1, or 4 (if the "Range" field is appended).

namespace ns3 {
//     class TcpOptionIR : TcpOption {
//       public:
//         enum EncodingType : uint8_t {
//             Undefined = 0,
//             XOR,
//             InterleavedFEC,
//             ReedSolomon
//         };

//         enum State : uint8_t {
//             None = 0,
//             Syned,
//             Connect
//         };

//         // Bit   Flag Name       Description
//         // 0     R_CWR           Congestion Window Reduction Acknowledgement
//         // 1     R_SUCCESS       Recovery successful
//         // 2     R_FAIL          Recovery failed
//         // 3     ENCODED         Packet is encoded
//         // 4-7
//         enum flags : uint8_t {
//             R_CWR = 0,      ///< [Bit 0] Congestion Window Reduction Acknowledgement
//             R_SUCCESS = 2U, ///< [Bit 1] Recovery successful
//             R_FAIL = 4U,    ///< [Bit 2] Recovery failed
//             ENCODED = 8U    ///< [Bit 3] Packet is encoded
//             // Bits 4-7 are reserved
//         };

//         static TypeId GetTypeId();

//         TcpOptionIR();
//         TcpOptionIR(bool isSyned);
//         void Serialize(Buffer::Iterator start) const;
//         uint32_t Deserialize(Buffer::Iterator start);
//         uint8_t GetKind() const;
//         uint32_t GetSerializedSize() const;
//         void Print(std::ostream& os);
//         uint8_t GetFlag() const;
//         uint8_t SetRecoveryStatus(bool stat);
//         uint8_t SetCWR(bool enable);
//         uint8_t SetEncoded(bool enable);
//         uint32_t GetRange() const;
//         void SetRange(uint32_t range);
//         EncodingType GetEncodingType() const;
//         void SetEncodingType(EncodingType algo);

//       private:
//         bool syned;
//         uint8_t flag;
//         uint8_t kind;
//         uint8_t length;
//         EncodingType encoding;
//         uint32_t range;
//     };

// same as tcpir, but ecc semgent is selectable
//                       1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +---------------+---------------+---------------+---------------+
//  |   Kind = TBD  |   Length = 4  |  (reserved) |E| Encoding Algo |
//  +---------------+---------------+---------------+---------------+
//        TCP-IRv2 Option format for packets with SYN flag set
//  flag E: the echo packet, if the receiver receive the syn packet with TCP-IR option, the
//  reciever SHOULD send this option with E=1 as response.
//                         1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +----------------+---------------+---------------+---------------
//  |   Kind = TBD   |    Length     |     Flags     |     Range
//  +----------------+---------------+---------------+--------------+
//    (optional)     |      ECC Range(if FLAG=8)     |   preserved  |
//  -----------------+-------------------------------+--------------+
//       TCP-IRv2 option format
// Range: The interpretation of this field depends on the context.
//        If Flags is set to 'Encoded', this field specifies the relative
//        range of the encoded block. The encoded block spans from the
//        current sequence number to (current sequence number + Range), inclusive.
//
// ECC Range: Specifies the range of redundant packets. The ECC packets
//            MUST be located at the very beginning of the encoded block.
//            Depending on the erasure coding algorithm used (e.g., systematic
//            codes), the ECC Range MUST be less than or equal to the Range
//            (i.e., ECC Range <= Range).
#define TCPIR_FLAG_E 0

    class TcpOptionIRv2 : public TcpOption {
      public:
        enum EncodingType : uint8_t {
            Undefined = 0,
            XOR,
            InterleavedFEC,
            ReedSolomon
        };

        enum State : uint8_t {
            None = 0,
            Syned,
            Received, // Implicit echo flag
            Connect
        };

        enum flags : uint8_t {
            R_CWR = 0,      ///< [Bit 0] Congestion Window Reduction Acknowledgement
            R_SUCCESS = 2U, ///< [Bit 1] Recovery successful
            R_FAIL = 4U,    ///< [Bit 2] Recovery failed
            ENCODED = 8U    ///< [Bit 3] Packet is encoded
            // Bits 4-7 are reserved
        };

        static TypeId GetTypeId();
        static std::string EncodingTypeToString(EncodingType type);
        TcpOptionIRv2();
        TcpOptionIRv2(State stat);
        void Serialize(Buffer::Iterator start) const;
        uint32_t Deserialize(Buffer::Iterator start);
        uint32_t GetSerializedSize() const;
        uint8_t GetKind() const;
        void Print(std::ostream& os) const;
        uint8_t GetFlag() const;
        uint8_t SetRecoveryStatus(bool stat);
        // uint8_t SetCWR(bool enable);
        void SetEncoded(bool enable);
        uint32_t GetRange() const;
        void SetRange(uint32_t range);
        EncodingType GetEncodingType() const;
        void SetEncodingType(EncodingType algo);
        void SetEccRange(uint16_t range);
        uint16_t GetEccRange() const;
        bool IsEcho() const;
        void SetEcho(bool enable);

      private:
        uint8_t kind;
        uint8_t length;
        uint8_t flag;
        State stat;
        bool echo;
        EncodingType encoding;
        uint16_t range;
        uint16_t ecc_range;
    };
} // namespace ns3
#endif // TCP_INSTENT_RECOVERY_H
