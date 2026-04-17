#include "mp-tcp-hash.h"

#include "ns3/hash.h"
#include "ns3/mp-tcp-typedefs.h"

#include <memory>
#include <openssl/hmac.h>

NS_LOG_COMPONENT_DEFINE("MpTcpHash");

namespace ns3 {

    void MpTcpMurMur::GetChecksumImpl(const std::vector<uint8_t>& data,
                                      void* out_buf,
                                      size_t request_len) const {
        NS_LOG_DEBUG("Murmur Checksum: data size=" << data.size()
                                                   << ", request_len=" << request_len);

        auto h = Hash::Function::Murmur3();
        uint64_t hash = h.GetHash64(reinterpret_cast<const char*>(data.data()), data.size());

        NS_LOG_DEBUG("Murmur raw hash=" << hash);

        uint8_t* hash_bytes = reinterpret_cast<uint8_t*>(&hash);
        size_t hash_len = sizeof(uint64_t);

        if (hash_len >= request_len) {
            memcpy(out_buf, hash_bytes, request_len);
        } else {
            memcpy(out_buf, hash_bytes, hash_len);
            memset(static_cast<uint8_t*>(out_buf) + hash_len, 0, request_len - hash_len);
        }
    }

    void MpTcpMurMur::GetHmacImpl(const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& message,
                                  void* out_buf,
                                  size_t request_len) const {
        NS_LOG_DEBUG("Murmur HMAC: key size=" << key.size() << ", message size=" << message.size()
                                              << ", request_len=" << request_len);

        auto h = Hash::Function::Murmur3();

        static constexpr size_t block_size = 64;
        static constexpr uint8_t ipad = 0x36;
        static constexpr uint8_t opad = 0x5c;

        std::vector<uint8_t> k(block_size, 0);

        if (key.size() > block_size) {
            uint64_t kh = h.GetHash64(reinterpret_cast<const char*>(key.data()), key.size());
            memcpy(k.data(), &kh, sizeof(kh));
            NS_LOG_DEBUG("Key hashed to 64-bit value=" << kh);
        } else if (!key.empty()) {
            memcpy(k.data(), key.data(), key.size());
        }

        std::vector<uint8_t> k_ipad(block_size);
        std::vector<uint8_t> k_opad(block_size);

        for (size_t i = 0; i < block_size; ++i) {
            k_ipad[i] = k[i] ^ ipad;
            k_opad[i] = k[i] ^ opad;
        }

        std::vector<uint8_t> inner_input;
        inner_input.reserve(block_size + message.size());
        inner_input.insert(inner_input.end(), k_ipad.begin(), k_ipad.end());
        inner_input.insert(inner_input.end(), message.begin(), message.end());

        uint64_t inner_hash =
            h.GetHash64(reinterpret_cast<const char*>(inner_input.data()), inner_input.size());

        NS_LOG_DEBUG("Inner hash=" << inner_hash);

        std::vector<uint8_t> outer_input;
        outer_input.reserve(block_size + sizeof(inner_hash));
        outer_input.insert(outer_input.end(), k_opad.begin(), k_opad.end());

        const uint8_t* inner_bytes = reinterpret_cast<const uint8_t*>(&inner_hash);
        outer_input.insert(outer_input.end(), inner_bytes, inner_bytes + sizeof(inner_hash));

        uint64_t final_hash =
            h.GetHash64(reinterpret_cast<const char*>(outer_input.data()), outer_input.size());

        NS_LOG_DEBUG("Final HMAC (Murmur)=" << final_hash);

        uint8_t* hash_bytes = reinterpret_cast<uint8_t*>(&final_hash);
        size_t hash_len = sizeof(uint64_t);

        if (hash_len >= request_len) {
            memcpy(out_buf, hash_bytes, request_len);
        } else {
            memcpy(out_buf, hash_bytes, hash_len);
            memset(static_cast<uint8_t*>(out_buf) + hash_len, 0, request_len - hash_len);
        }
    }

    void MpTcpSHA256::GetChecksumImpl(const std::vector<uint8_t>& data,
                                      void* out_buf,
                                      size_t request_len) const {
        NS_LOG_DEBUG("SHA256 Checksum: data size=" << data.size()
                                                   << ", request_len=" << request_len);

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(data.data(), data.size(), hash);

        NS_LOG_DEBUG("SHA256 computed");

        size_t hash_len = SHA256_DIGEST_LENGTH;
        if (hash_len >= request_len) {
            memcpy(out_buf, hash, request_len);
        } else {
            memcpy(out_buf, hash, hash_len);
            memset(static_cast<uint8_t*>(out_buf) + hash_len, 0, request_len - hash_len);
        }
    }

    void MpTcpSHA256::GetHmacImpl(const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& message,
                                  void* out_buf,
                                  size_t request_len) const {
        NS_LOG_DEBUG("SHA256 HMAC: key size=" << key.size() << ", message size=" << message.size()
                                              << ", request_len=" << request_len);

        unsigned char hmac[SHA256_DIGEST_LENGTH];
        HMAC(EVP_sha256(), key.data(), key.size(), message.data(), message.size(), hmac, nullptr);

        NS_LOG_DEBUG("SHA256 HMAC computed");

        size_t hash_len = SHA256_DIGEST_LENGTH;
        if (hash_len >= request_len) {
            memcpy(out_buf, hmac, request_len);
        } else {
            memcpy(out_buf, hmac, hash_len);
            memset(static_cast<uint8_t*>(out_buf) + hash_len, 0, request_len - hash_len);
        }
    }

    std::shared_ptr<MpTcpHash> MpTcpHashFactory::Create(checksum_algo algo) {
        std::map<checksum_algo, std::string> name_of_algo = {{HMAC_MURMUR3, "HMAC_MURMUR3"},
                                                             {HMAC_SHA256, "HMAC_SHA256"},
                                                             {HMAC_UNKNOW, "HMAC_UNKNOW"}};
        NS_LOG_FUNCTION(this << algo);
        switch (algo) {
        case checksum_algo::HMAC_MURMUR3:
            return std::make_shared<MpTcpMurMur>();
        case checksum_algo::HMAC_SHA256:
            return std::make_shared<MpTcpSHA256>();
        case checksum_algo::HMAC_UNKNOW:
        default:
            break;
        }
        return nullptr;
    }

} // namespace ns3
