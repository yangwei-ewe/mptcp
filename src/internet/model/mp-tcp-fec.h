#ifndef MP_TCP_FEC_H
#define MP_TCP_FEC_H
#include <ns3/packet.h>

namespace ns3 {

    enum FecAlogrithm : uint8_t {
        XOR,
        RaptorCode
    };

    class MpTcpFec {
      public:
        MpTcpFec(int symb_len);
        ~MpTcpFec();
        virtual std::vector<Packet> Encode();
        virtual std::vector<Packet> Decode();

      protected:
        size_t symbol_len;
        virtual void EncodeImpl() = 0;
        virtual void DecodeImpl() = 0;
    };

    class XorFec : public MpTcpFec {
      public:
        XorFec();
        ~XorFec();

      protected:
        void EncodeImpl() override;
        void DecodeImpl() override;
    };

    class RaptorCodeFec : public MpTcpFec {
      public:
        RaptorCodeFec();
        ~RaptorCodeFec();

      protected:
        void EncodeImpl() override;
        void DecodeImpl() override;
    };

    class MpTcpFecFactory {
      public:
        std::shared_ptr<MpTcpFec> Create(FecAlogrithm algo);
    };
} // namespace ns3

#endif // MP_TCP_FEC_H
