#ifndef MP_TCP_HASH_H
#define MP_TCP_HASH_H

#include "ns3/hash-murmur3.h"
#include "ns3/object.h"

#include <openssl/sha.h>

namespace ns3 {
    enum checksum_algo : uint8_t { // represent bit map
        HMAC_SHA256 = 1,
        HMAC_MURMUR3 =
            2, // replace sha256 with murmur3 cause there is no sha256 implementation in ns3
        HMAC_UNKNOW = 0xff // must drop the package if algo is not specified
    };

    class MpTcpHash {
      public:
        virtual ~MpTcpHash() = default;

        std::vector<uint8_t> GetChecksumL(size_t len, const std::vector<uint8_t>& data) const {
            std::vector<uint8_t> result(len);
            GetChecksumImpl(data, &result, len);
            return result;
        }

        template <typename T>
        T GetChecksum(const std::vector<uint8_t>& data) const {
            T result{};
            GetChecksumImpl(data, &result, sizeof(T));
            return result;
        }

        template <typename T, typename U>
        T GetChecksum(const U& data) const {
            std::vector<uint8_t> _data(sizeof(U), 0);
            memcpy(_data.data(), &data, sizeof(U));
            T result{};
            GetChecksumImpl(_data, &result, sizeof(T));
            return result;
        }

        // for those too long to seal in language-defined data type e.g. hamc160
        std::vector<uint8_t> GetHmacL(size_t len,
                                      const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& msg) const {
            std::vector<uint8_t> result(len);
            GetHmacImpl(key, msg, result.data(), len);
            return result;
        }

        template <typename T, typename U> // e.g. uint64_t, uint16_t, uint8_t, etc.
        T GetHmac(const U& key, const U& msg) const {
            T result{};
            std::vector<uint8_t> _key(sizeof(U), 0);
            memcpy(_key.data(), &key, sizeof(U));
            std::vector<uint8_t> _msg(sizeof(U), 0);
            memcpy(_msg.data(), &msg, sizeof(U));
            GetHmacImpl(_key, _msg, &result, sizeof(T));
            return result;
        }

      protected:
        virtual void GetChecksumImpl(const std::vector<uint8_t>& data,
                                     void* out_buf,
                                     size_t request_len) const = 0;
        virtual void GetHmacImpl(const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& message,
                                 void* out_buf,
                                 size_t request_len) const = 0;
    };

    class MpTcpMurMur : public MpTcpHash {
      protected:
        virtual void GetChecksumImpl(const std::vector<uint8_t>& data,
                                     void* out_buf,
                                     size_t request_len) const override;
        virtual void GetHmacImpl(const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& message,
                                 void* out_buf,
                                 size_t request_len) const override;
    };

    class MpTcpSHA256 : public MpTcpHash {
      protected:
        virtual void GetChecksumImpl(const std::vector<uint8_t>& data,
                                     void* out_buf,
                                     size_t request_len) const override;
        virtual void GetHmacImpl(const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& message,
                                 void* out_buf,
                                 size_t request_len) const override;
    };

    // class MpTcpHashUnImpl : public MpTcpHash {
    //   protected:
    //     virtual void GetChecksumImpl(checksum_algo algo,
    //                                  const std::vector<uint8_t>& data,
    //                                  void* out_buf,
    //                                  size_t request_len) const = 0;
    //     virtual void GetHmacImpl(checksum_algo algo,
    //                              const std::vector<uint8_t>& key,
    //                              const std::vector<uint8_t>& message,
    //                              void* out_buf,
    //                              size_t request_len) const = 0;
    // };

    class MpTcpHashFactory {
      public:
        std::shared_ptr<MpTcpHash> Create(checksum_algo);
    };
} // namespace ns3
#endif // MP_TCP_HASH_H
