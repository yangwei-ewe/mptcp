#ifndef MP_TCP_TYPEDEFS_H
#define MP_TCP_TYPEDEFS_H

#include "mp-tcp-subflow.h"

#include "ns3/event-id.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-end-point.h"
#include "ns3/ipv6-address.h"
#include "ns3/mp-tcp-hash.h"
#include "ns3/node.h"
#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/rtt-estimator.h"
#include "ns3/sequence-number.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/tcp-option.h"
#include "ns3/tcp-socket.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/traced-value.h"
#include "ns3/uinteger.h"

#include <list>
#include <map>
#include <queue>
#include <set>
#include <stdint.h>
#include <vector>

using namespace std;

#define PKG_SETHIGHU8(flag, value)                                                                 \
    {                                                                                              \
        flag = ((flag & 0x0fU) + ((value << 4) & 0xf0U));                                          \
    }
#define PKG_GETHIGHU8(flag) static_cast<uint8_t>(flag >> 4)
#define PKG_SETLOWU8(flag, value)                                                                  \
    {                                                                                              \
        flag = ((flag & 0xf0U) + (value & 0x0fU));                                                 \
    }
#define PKG_GETLOWU8(flag) {static_cast<uint8_t>(flag & 0x0fU)}
#define PKG_SETSUBTYPEU8(flag, value) PKG_SETHIGHU8(flag, value)
#define PKG_GETSUBTYPEU8(flag) static_cast<MP_SubType>(PKG_GETHIGHU8(flag))

namespace ns3 {

/**
 * @brief print error_msg if cond is true, but dont exit
 */
#define TEST(cond, message, then)                                                                  \
    {                                                                                              \
        if (cond) {                                                                                \
            NS_FATAL_ERROR_CONT(message);                                                          \
            then                                                                                   \
        }                                                                                          \
    }

/**
 * @brief print error_msg as fatal msg then exit if cond is true
 */
#define ASSERT(cond, error_msg)                                                                    \
    do {                                                                                           \
        if (cond) {                                                                                \
            NS_FATAL_ERROR(error_msg);                                                             \
        }                                                                                          \
    } while (false)

    inline void set_bit8(uint8_t& flag, uint8_t offset) {
        (flag) |= (1U << (offset));
        return;
    }

    inline bool get_bit8(uint8_t& flag, uint8_t offset) {
        return (1U & (flag >> offset));
    }

    inline void clear_bit8(uint8_t& flag, uint8_t offset) {
        flag &= ~(1U << (offset));
        return;
    }

    typedef enum {
        MP_NONE, // 0
        MP_SYNED,
        MP_MPC, // 1
        MP_ADDR // 2
        // MP_JOIN
    } MpStates_t;

    typedef enum {
        Uncoupled_TCPs,       // 0
        Linked_Increases,     // 1
        RTT_Compensator,      // 2
        Fully_Coupled,        // 3
        COUPLED_SCALABLE_TCP, // 4
        UNCOUPLED,            // 5
        COUPLED_EPSILON,      // 6
        COUPLED_INC,          // 7
        COUPLED_FULLY         // 8
    } CongestionCtrl_t;

    typedef enum {
        Round_Robin
    } DataDistribAlgo_t;

    enum PathPolicy {
        Default,
        FullMesh,
        NdiffPorts
    };

    enum Reason : uint8_t {                 // Reset reason for MP_TCPRST
        UNSPECIFIED_ERROR = 0x00,           // Unspecified error
        MPTCP_SPECIFIC_ERROR = 0x01,        // MPTCP-specific error
        LACK_OF_RESOURCES = 0x02,           // Lack of resources
        ADMINISTRATIVELY_PROHIBITED = 0x03, // Administratively prohibited
        TOO_MUCH_OUTSTANDING_DATA = 0x04,   // Too much outstanding data
        UNACCEPTABLE_PERFORMANCE = 0x05,    // Unacceptable performance
        MIDDLEBOX_INTERFERENCE = 0x06       // Middlebox interference
    };

    enum MP_SubType : uint8_t { // the MPTCP option subtype codes defined by rfc 8684
        MP_CAPABLE = 0,         // Multipath Capable
        MP_JOIN = 1,            // Join Connection
        DSS = 2,                // Data Sequence Signal (Data ACK and Data Sequence Mapping)
        ADD_ADDR = 3,           // Add Address
        REMOVE_ADDR = 4,        // Remove Address
        MP_PRIO = 5,            // Change Subflow Priority
        MP_FAIL = 6,            // Fallback
        MP_FASTCLOSE = 7,       // Fast Close
        MP_TCPRST = 8,          // Subflow Reset
        MP_EXPERIMENT = 0xf     // Reserved for Private Use
    };

    class Path;

    class MpTcpAddressInfo {
      public:
        MpTcpAddressInfo();
        MpTcpAddressInfo(Ipv4Address ipv4Addr, uint16_t port)
            : ipv4Addr(ipv4Addr),
              port(port),
              path(nullptr) {};
        ~MpTcpAddressInfo();
        uint8_t addrID;
        Ipv4Address ipv4Addr;
        Ipv4Mask mask;
        uint16_t port;
        uint32_t hash;
        bool acked;
        shared_ptr<Path> path;
    };

    class Path {
      private:
        shared_ptr<MpTcpAddressInfo> src_addr_info;  // to bind addr_info
        shared_ptr<MpTcpAddressInfo> dest_addr_info; // to bind addr_info
        Ptr<MpTcpSubFlow> subflow;

      public:
        // bool check_sflow_exist() const;
        Path(shared_ptr<MpTcpAddressInfo> src_addr_info,
             shared_ptr<MpTcpAddressInfo> dest_addr_info);
        Path(shared_ptr<MpTcpAddressInfo> listen_addr_info);
        ~Path();
        void Update(shared_ptr<MpTcpAddressInfo> dest_addr_info);
        void Detach();
        std::pair<shared_ptr<MpTcpAddressInfo>, shared_ptr<MpTcpAddressInfo>> get_route()
            const; //<local_addrs, remote_addrs>
        Ptr<MpTcpSubFlow> get_subflow() const;
        void set_subflow(Ptr<MpTcpSubFlow> sf);
        friend ostream& operator<<(ostream& s, const Path& p);
    };

    /**
     * @brief PathManager manages all the addresses both local address and remote address, and the
     * subflow connection between them.
     * @note for the efficiency concern, we pass address of address info instead of index of
     * address.
     */
    class PathManager {
        // friend class PathManager::iterator;
        //   private:

      public:
        enum addr_t {
            local = 0,
            remote = 1
        };

        uint8_t maxSubflow;
        // Ptr<Node> m_node;
        // Ptr<TcpL4Protocol> m_tcp;
        // Ptr<MpTcpSocketBase> mptcp;
        map<uint8_t, shared_ptr<Path>> links;
        map<uint8_t, shared_ptr<MpTcpAddressInfo>> localAddrs;
        map<uint8_t, shared_ptr<MpTcpAddressInfo>> remoteAddrs;

        PathManager()
            : maxSubflow(UINT8_MAX) {
        }

        PathManager(uint8_t maxSubflow) {
            this->maxSubflow = maxSubflow;
        }

        void set_max_subflow(uint8_t max_subflow);
        int add_address(addr_t type, MpTcpAddressInfo addrInfo);
        int is_addr_exist(addr_t type, Ipv4Address addr);
        shared_ptr<MpTcpAddressInfo> get_address_info(addr_t type, uint8_t addr_id) const;
        void remove_address(addr_t type, uint8_t addr_id);
        shared_ptr<Path> get_path_from_addr(uint8_t addr_id) const;
        void remove_path(uint8_t subflow_id);
        int create_path(uint8_t src_id,
                        uint8_t dest_id,
                        Ptr<NetDevice> NetDev_of_src,
                        Ptr<TcpL4Protocol> tcp);
        int bind(uint8_t dest_id, Ptr<NetDevice> NetDev_of_src, Ptr<TcpL4Protocol> tcp);
        bool update_remote_addr(uint8_t subflow_idx, uint8_t remote_id);
        Ptr<MpTcpSubFlow> get_subflow(uint8_t sFlowId) const;
        uint8_t gen_route_id();

        shared_ptr<Path> operator[](uint8_t subflow_idx) {
            return this->links[subflow_idx];
        }

        std::map<uint8_t,
                 std::shared_ptr<ns3::Path>,
                 std::less<uint8_t>,
                 std::allocator<std::pair<const uint8_t, std::shared_ptr<ns3::Path>>>>::iterator
        begin() {
            return this->links.begin();
        }

        std::map<uint8_t,
                 std::shared_ptr<ns3::Path>,
                 std::less<uint8_t>,
                 std::allocator<std::pair<const uint8_t, std::shared_ptr<ns3::Path>>>>::iterator
        end() {
            return this->links.end();
        }

        std::map<uint8_t,
                 std::shared_ptr<ns3::Path>,
                 std::less<uint8_t>,
                 std::allocator<std::pair<const uint8_t, std::shared_ptr<ns3::Path>>>>::iterator
        operator++(int) {
            std::map<uint8_t,
                     std::shared_ptr<ns3::Path>,
                     std::less<uint8_t>,
                     std::allocator<std::pair<const uint8_t, std::shared_ptr<ns3::Path>>>>::iterator
                retval = this->links.begin();
            ++(this->links.begin());
            return retval;
        }

        /**
         * @brief Get the current number of subflows in the path manager.
         *
         * @return size_t
         */
        size_t size() const {
            return this->links.size();
        }
    };

    class DSNMapping {
      public:
        DSNMapping();
        DSNMapping(uint8_t sFlowIdx,
                   uint64_t dSeqNum,
                   uint16_t dLvlLen,
                   uint32_t sflowSeqNum,
                   uint32_t ack /*, Ptr<Packet> pkt*/);
        // DSNMapping (const DSNMapping &res);
        virtual ~DSNMapping();
        bool operator<(const DSNMapping& rhs) const;
        uint64_t dataSeqNumber;
        uint16_t dataLevelLength;
        uint32_t subflowSeqNumber;
        uint32_t acknowledgement;
        uint32_t dupAckCount;
        uint8_t subflowIndex;
        // uint8_t *packet;
    };

    struct pkg_header {
        uint8_t kind;
        uint8_t length;
        uint8_t _buf : 4; // unused here, out scope
        MP_SubType subtype : 4;
    };

    class pkg_undefine : public Object {
      private:
        uint8_t kind;
        uint8_t length;
        MP_SubType subtype;
        Buffer _data;

      public:
        pkg_undefine();
        pkg_undefine(pkg_header header);

        virtual ~pkg_undefine() {
        }

        virtual Buffer Serialize();
        virtual uint32_t Deserialize(Buffer::Iterator);
        virtual uint8_t CalculateLength();

        virtual uint8_t GetKind() const {
            return this->kind;
        };

        virtual MP_SubType GetSubtype() const {
            return this->subtype;
        };

        virtual uint8_t GetLength() const

        {
            return this->length;
        };

        static TypeId GetTypeId();

        static std::string GetName() {
            return "option: unknow / experiment";
        }
    };

    class TcpOptionMptcp : public TcpOption {
      private:
        // uint8_t kind;
        // uint8_t length;
        // MP_SubType subtype;
        Ptr<pkg_undefine> pkg;

      public:
        static TypeId GetTypeId(void);
        TcpOptionMptcp();
        TcpOptionMptcp(MP_SubType subtype);

        ~TcpOptionMptcp() override {
        }

        void Print(std::ostream& os) const override {
            os << "MPTCP Option: " << this->pkg->GetName() << ", Kind=" << +this->GetKind()
               << ", Length=" << +this->pkg->GetLength();
        }

        uint32_t GetSerializedSize() const override {
            return this->pkg->CalculateLength();
        }

        bool is_known_subtype(uint8_t subtype) const;
        void Serialize(Buffer::Iterator start) const override;
        uint32_t Deserialize(Buffer::Iterator start) override;

        MP_SubType GetSubType() const {
            return this->pkg->GetSubtype();
        }

        virtual std::string GetSubtypeName() const {
            std::unordered_map<MP_SubType, std::string> subtypeName = {
                {MP_CAPABLE, "MP_CAPABLE"},
                {MP_JOIN, "MP_JOIN"},
                {DSS, "DSS"},
                {ADD_ADDR, "ADD_ADDR"},
                {REMOVE_ADDR, "REMOVE_ADDR"},
                {MP_PRIO, "MP_PRIO"},
                {MP_FAIL, "MP_FAIL"},
                {MP_FASTCLOSE, "MP_FASTCLOSE"},
                {MP_TCPRST, "MP_TCPRST"},
                {MP_EXPERIMENT, "MP_EXPERIMENT"}};
            return subtypeName[this->GetSubType()];
        };

        static std::string GetSubtypeName(MP_SubType subtypeId) {
            std::unordered_map<MP_SubType, std::string> subtypeName = {
                {MP_CAPABLE, "MP_CAPABLE"},
                {MP_JOIN, "MP_JOIN"},
                {DSS, "DSS"},
                {ADD_ADDR, "ADD_ADDR"},
                {REMOVE_ADDR, "REMOVE_ADDR"},
                {MP_PRIO, "MP_PRIO"},
                {MP_FAIL, "MP_FAIL"},
                {MP_FASTCLOSE, "MP_FASTCLOSE"},
                {MP_TCPRST, "MP_TCPRST"},
                {MP_EXPERIMENT, "MP_EXPERIMENT"}};
            return subtypeName[subtypeId];
        };

        uint8_t GetKind() const override;
        Ptr<pkg_undefine> GetPackage();
        Ptr<const pkg_undefine> GetPackage() const;
        void SetSubType(MP_SubType subtype);
        // MP_SubType GetSubType() const;
    };

#define PKG_SETHIGHU8(flag, value)                                                                 \
    {                                                                                              \
        flag = ((flag & 0x0fU) + ((value << 4) & 0xf0U));                                          \
    }
#define PKG_GETHIGHU8(flag) static_cast<uint8_t>(flag >> 4)
#define PKG_SETLOWU8(flag, value)                                                                  \
    {                                                                                              \
        flag = ((flag & 0xf0U) + (value & 0x0fU));                                                 \
    }
#define PKG_GETLOWU8(flag) {static_cast<uint8_t>(flag & 0x0fU)}
#define PKG_SETSUBTYPEU8(flag, value) PKG_SETHIGHU8(flag, value)
#define PKG_GETSUBTYPEU8(flag) static_cast<MP_SubType>(PKG_GETHIGHU8(flag))

// MP_CAPABLE
//                     1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +---------------+---------------+-------+-------+---------------+
// |     Kind      |    Length     |Subtype|Version|A|B|C|D|E|F|G|H|
// +---------------+---------------+-------+-------+---------------+
// |                   Option Sender's Key (64 bits)               |
// |                      (if option Length > 4)                   |
// +---------------------------------------------------------------+
// |                  Option Receiver's Key (64 bits)              |
// |                      (if option Length > 12)                  |
// +-------------------------------+-------------------------------+
// |  Data-Level Length (16 bits)  |  Checksum (16 bits, optional) |
// +-------------------------------+-------------------------------+
#define MP_CAPABLE_FLAG_A 7
#define MP_CAPABLE_FLAG_B 6
#define MP_CAPABLE_FLAG_C 5
#define MP_CAPABLE_FLAG_H 1

    /**
     * for the MP_CAPABLE.flag:
     * A: should be set as 1, which means "require checksum"
     * B: preserved, must be set as 0 in this version
     * C: set to 1 to indicate that the sender of this option will not accept additional MPTCP
     * subflows to the source address and port H: use of HMAC-SHA256. An implementation that only
     * supports this method MUST set bit "H" to 1 and bits "D" through "G" to 0.Furthermore, if D~H
     * are all 0, the MP_CAPABLE should be treated as invalid and ignored(i.e. back to TCP
     * handshake)
     */
    class pkg_mp_capable : public pkg_undefine {
      public:
        static TypeId GetTypeId();
        pkg_mp_capable();
        pkg_mp_capable(pkg_header header);

        ~pkg_mp_capable() {
        }

        Buffer Serialize() override;
        uint32_t Deserialize(Buffer::Iterator buffer) override;
        uint8_t CalculateLength() override;

        static std::string GetName() {
            return "option: MP_CAPABLE";
        }

        MP_SubType GetSubtype() const override {
            return this->subtype;
        }

        uint8_t get_length() const {
            return length;
        }

        uint8_t get_version() const {
            return version;
        }

        void set_version(uint8_t v) {
            this->version = v;
        }

        uint64_t get_sender_key() const {
            return sender_key;
        }

        void set_sender_key(uint64_t senderKey) {
            sender_key = senderKey;
        }

        uint64_t get_receiver_key() const {
            return receiver_key;
        }

        void set_receiver_key(uint64_t receiverKey) {
            receiver_key = receiverKey;
        }

        uint16_t get_data_level_length() const {
            return data_level_length;
        }

        void set_data_level_length(uint16_t length) {
            data_level_length = length;
        }

        uint16_t get_checksum() const {
            return checksum;
        }

        void set_checksum(uint16_t checksum) {
            checksum = checksum;
        }

        bool is_checksum_require() const {
            return _is_checksum_require;
        }

        void set_checksum_require(bool require) {
            _is_checksum_require = require;
        }

        bool get_preserved() const {
            return preserved;
        }

        void set_preserved(bool preserved) {
            preserved = preserved;
        }

        bool no_more_subflow() const {
            return _no_more_subflow;
        }

        void set_no_more_subflow(bool enable) {
            _no_more_subflow = enable;
        }

        bool with_first_data() const {
            return _with_first_data;
        }

        void set_with_first_data(bool enable) {
            _with_first_data = enable;
        }

        checksum_algo get_checksum_algo() const {
            return _checksum_algo;
        }

        void set_checksum_algo(checksum_algo algo) {
            _checksum_algo = algo;
        }

        // ===== 原本已有的方法可保留 =====
        bool is_checksum_enable() const {
            return this->_is_checksum_require;
        }

      private:
        uint8_t kind;
        uint8_t length;
        MP_SubType subtype;
        uint8_t version;
        uint64_t sender_key;
        uint64_t receiver_key;
        uint16_t data_level_length;
        uint16_t checksum;         // optional
        bool _is_checksum_require; // A
        bool preserved;            // B, must be 0 in this version
        bool _no_more_subflow;     // C
        bool _with_first_data;
        checksum_algo _checksum_algo;
    };

    //    Host A                             Host B
    //    ------                             ------
    //    MP_JOIN               ->
    //    [B's token, A's nonce,
    //     A's Address ID, flags]
    //                          <-           MP_JOIN
    //                                       [B's HMAC, B's nonce,
    //                                        B's Address ID, flags]
    //    ACK + MP_JOIN         ->
    //    [A's HMAC]
    //                          <-           ACK

    //           Host A                                  Host B
    // ------------------------                       ----------
    // Address A1    Address A2                       Address B1
    // ----------    ----------                       ----------
    //     |             |                                |
    //     |             |  SYN + MP_CAPABLE              |
    //     |--------------------------------------------->|
    //     |<---------------------------------------------|
    //     |          SYN/ACK + MP_CAPABLE(Key-B)         |
    //     |             |                                |
    //     |        ACK + MP_CAPABLE(Key-A, Key-B)        |
    //     |--------------------------------------------->|
    //     |             |                                |
    //     |             |   SYN + MP_JOIN(Token-B, R-A)  |
    //     |             |------------------------------->|
    //     |             |<-------------------------------|
    //     |             | SYN/ACK + MP_JOIN(HMAC-B, R-B) |
    //     |             |                                |
    //     |             |     ACK + MP_JOIN(HMAC-A)      |
    //     |             |------------------------------->|
    //     |             |<-------------------------------|
    //     |             |             ACK                |

    // HMAC-A = HMAC(Key=(Key-A + Key-B), Msg=(R-A + R-B))
    // HMAC-B = HMAC(Key=(Key-B + Key-A), Msg=(R-B + R-A))

#define MP_JOIN_FLAG_B 0

    enum JoinState_t : uint8_t {
        JOIN_NONE = 0,
        JOIN_SYN,
        JOIN_SYNACK,
        JOIN_ACKED,
        JOIN_ACK_CONFIRM
    };

    class pkg_mp_join : public pkg_undefine {
      private:
        uint8_t kind;
        uint8_t length;
        MP_SubType subtype;
        shared_ptr<MpTcpHash> hash;
        JoinState_t state;
        bool backup; // flag b
        uint8_t address_id;
        uint32_t receiver_token;
        uint32_t sender_random;
        uint64_t truncated_hmac_64;
        uint8_t truncated_hmac_160[20];

      public:
        static TypeId GetTypeId();

        pkg_mp_join();
        pkg_mp_join(pkg_header header);

        // uint32_t gen_token(uint32_t key) const;

        // bool check(uint32_t key) const const {
        //     auto fake_token = this->gen_token(key);
        //     return (fake_token == this->receiver_token);
        // }

        bool check(uint32_t key, uint32_t message);

        static std::string GetName() {
            return "option: MP_JOIN";
        }

        void SetState(JoinState_t s) {
            state = s;
        }

        JoinState_t GetState() const {
            return state;
        }

        MP_SubType GetSubtype() const override {
            return this->subtype;
        }

        // ===============================
        // 🔹 基本欄位 Getter / Setter
        // ===============================

        bool is_backup() const {
            return backup;
        }

        void set_backup_flag(bool enable) {
            backup = enable;
        }

        uint8_t get_address_id() const {
            return address_id;
        }

        void set_address_id(uint8_t id) {
            address_id = id;
        }

        uint32_t get_sender_random() const {
            return sender_random;
        }

        void set_sender_random(uint32_t rnd) {
            sender_random = rnd;
        }

        uint32_t get_receiver_token() const {
            return receiver_token;
        }

        void set_receiver_token(uint32_t token) {
            receiver_token = token;
        }

        uint64_t get_truncated_hmac64() const {
            return truncated_hmac_64;
        }

        void set_truncated_hmac64(uint64_t h) {
            truncated_hmac_64 = h;
        }

        const uint8_t* get_truncated_hmac160() const {
            return truncated_hmac_160;
        }

        void set_truncated_hmac160(const uint8_t* hmac20) {
            memcpy(truncated_hmac_160, hmac20, 20);
        }

        Buffer Serialize() override;
        uint32_t Deserialize(Buffer::Iterator buffer) override;
        uint8_t CalculateLength() override;
    };

    // persudo-header of DSS checksum
    //                       1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +--------------------------------------------------------------+
    //  |                                                              |
    //  |                Data Sequence Number (8 octets)               |
    //  |                                                              |
    //  +--------------------------------------------------------------+
    //  |              Subflow Sequence Number (4 octets)              |
    //  +-------------------------------+------------------------------+
    //  |  Data-Level Length (2 octets) |        Zeros (2 octets)      |
    //  +-------------------------------+------------------------------+

    // data sequence signal
    //                     1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +---------------+---------------+-------+----------------------+
    // |     Kind      |    Length     |Subtype| (reserved) |F|m|M|a|A|
    // +---------------+---------------+-------+----------------------+
    // |           Data ACK (4 or 8 octets, depending on flags)       |
    // +--------------------------------------------------------------+
    // |   Data Sequence Number (4 or 8 octets, depending on flags)   |
    // +--------------------------------------------------------------+
    // |              Subflow Sequence Number (4 octets)              |
    // +-------------------------------+------------------------------+
    // |  Data-Level Length (2 octets) |      Checksum (2 octets)     |
    // +-------------------------------+------------------------------+

    /**
     * flag of dss:
     * F (Data FIN): present data fin like tcp.
     * m (DSN length): Data Sequence Number is 8 octets (if not set, DSN is 4 octets)
     * M (Mapping present): Data Sequence Number (DSN), Subflow Sequence Number (SSN), Data-Level
     * Length, and Checksum (if negotiated) present a (Data ACK length): Data ACK is 8 octets (if
     * not set, Data ACK is 4 octets) A (Data ACK present): Data ACK present
     */

#define MP_DSS_FLAG_F 4
#define MP_DSS_FLAG_m 3
#define MP_DSS_FLAG_M 2
#define MP_DSS_FLAG_a 1
#define MP_DSS_FLAG_A 0

    class pkg_mp_dss : public pkg_undefine {
      private:
        uint8_t kind;
        uint8_t length;
        MP_SubType subtype;

        bool _is_fin;      // DATA_FIN
        bool _is_wide_dsn; // DSN 64bit
        bool dsn_present;  // DSN present
        bool _is_wide_ack; // ACK 64bit
        bool _is_ack;      // ACK present

        // optional fields
        uint64_t _data_ack;
        uint64_t _data_seq;
        uint32_t _subflow_seq;
        uint16_t data_level_length;
        uint16_t checksum;

      public:
        static TypeId GetTypeId();
        pkg_mp_dss();
        pkg_mp_dss(pkg_header header);

        ~pkg_mp_dss() {
        }

        static std::string GetName() {
            return "option: MP_DSS";
        }

        MP_SubType GetSubtype() const override {
            return this->subtype;
        }

        // ===== Getter / Setter =====
        uint8_t get_kind() const {
            return this->kind;
        }

        void set_kind(uint8_t kind) {
            this->kind = kind;
        }

        uint8_t get_length() const {
            return this->length;
        }

        void set_length(uint8_t length) {
            this->length = length;
        }

        MP_SubType get_subtype() const {
            return this->subtype;
        }

        void set_subtype(MP_SubType subtype) {
            this->subtype = subtype;
        }

        // ===== flag control =====

        bool is_ack() const {
            return this->_is_ack;
        }

        void set_has_data_ack(bool enable) {
            this->_is_ack = enable;
        }

        bool has_data_seq() const {
            return this->dsn_present;
        }

        void set_has_data_seq(bool enable) {
            this->dsn_present = enable;
        }

        bool use_64bit_ack() const {
            return this->_is_wide_ack;
        }

        void set_use_64bit_ack(bool enable) {
            this->_is_wide_ack = enable;
        }

        bool use_64bit_seq() const {
            return this->_is_wide_dsn;
        }

        void set_use_64bit_seq(bool enable) {
            this->_is_wide_dsn = enable;
        }

        bool is_fin() const {
            return this->_is_fin;
        }

        void set_fin(bool enable) {
            this->_is_fin = enable;
        }

        // ===== data ack =====
        uint64_t get_data_ack() const {
            return this->_data_ack;
        }

        void set_data_ack(uint64_t v) {
            this->_data_ack = v;
        }

        // ===== data seq =====
        uint64_t get_data_seq() const {
            return this->_data_seq;
        }

        void set_data_seq(uint64_t v) {
            this->_data_seq = v;
        }

        // ===== subflow seq =====
        uint32_t get_subflow_seq() const {
            return this->_subflow_seq;
        }

        void set_subflow_seq(uint32_t v) {
            this->_subflow_seq = v;
        }

        // ===== data length =====
        uint16_t get_data_level_length() const {
            return this->data_level_length;
        }

        void set_data_level_length(uint16_t len) {
            this->data_level_length = len;
        }

        bool verify_checksum();
        uint16_t update_checksum();

        // ===== override =====
        Buffer Serialize() override;
        uint32_t Deserialize(Buffer::Iterator buffer) override;
        uint8_t CalculateLength() override;
    };

    // mp_prio
    //                        1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +---------------+---------------+-------+-----+-+
    // |     Kind      |     Length    |Subtype|(rsv)|B|
    // +---------------+---------------+-------+-----+-+
    /**
     * flag of mp_prio:
     * B: backup
     */

#define MP_PRIO_FLAG_B 0

    class pkg_mp_prio : public pkg_undefine {
      public:
        uint8_t kind;
        uint8_t length;
        MP_SubType subtype;
        bool backup; // B flag
      public:
        static TypeId GetTypeId();
        pkg_mp_prio();
        pkg_mp_prio(pkg_header header);
        ~pkg_mp_prio() {};

        static std::string GetName() {
            return "option: MP_PRIO";
        }

        MP_SubType GetSubtype() const override {
            return this->subtype;
        }

        void set_backup(bool enable) {
            this->backup = enable;
        }

        bool is_backup() const {
            return this->backup;
        }

        Buffer Serialize() override;
        uint32_t Deserialize(Buffer::Iterator buffer) override;
        uint8_t CalculateLength() override;
    };

//  ADD_ADDR
//                        1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +---------------+---------------+-------+-------+---------------+
// |     Kind      |     Length    |Subtype|(rsv)|E|  Address ID   |
// +---------------+---------------+-------+-------+---------------+
// |           Address (IPv4: 4 octets / IPv6: 16 octets)          |
// +-------------------------------+-------------------------------+
// |   Port (2 octets, optional)   |                               |
// +-------------------------------+                               |
// |                Truncated HMAC (8 octets, if E=0)              |
// |                               +-------------------------------+
// |                               |
// +-------------------------------+

/**
 * flag of ADD_ADDR:
 * E: when receiver received the ADD_ADDR option form sender(E=0), as response, receiver must send a
 * echo where E=1 and without HMAC
 */
#define MP_ADD_ADDR_FLAG_E 0

    class pkg_mp_add_addr : public pkg_undefine {
      private:
        uint8_t kind;
        uint8_t length;
        MP_SubType subtype;
        bool echo; // E flag
        uint8_t address_id;

        bool _is_ipv6;
        Ipv4Address ipv4Addr; //!< stored IPv4 address when _is_ipv6 == false
        Ipv6Address ipv6Addr; //!< stored IPv6 address when _is_ipv6 == true

        bool has_port;
        uint16_t port;

        uint64_t truncated_hmac; // only if E == 0
        void mk_hmac();

      public:
        static TypeId GetTypeId();
        pkg_mp_add_addr();
        pkg_mp_add_addr(pkg_header header);

        Buffer Serialize() override;
        uint32_t Deserialize(Buffer::Iterator buffer) override;
        uint8_t CalculateLength() override;

        static std::string GetName() {
            return "option: ADD_ADDR";
        }

        MP_SubType GetSubtype() const override {
            return this->subtype;
        }

        bool with_port() const {
            return has_port;
        }

        bool is_echo() const {
            return echo;
        }

        void set_echo(bool echo = false) {
            this->echo = echo;
        }

        uint8_t GetAddressId() const {
            return address_id;
        }

        void SetAddressId(uint8_t id) {
            address_id = id;
        }

        /// Set an IPv4 address (clears IPv6 flag)
        void SetAddress(Ipv4Address addr) {
            _is_ipv6 = false;
            ipv4Addr = addr;
        }

        /// Set an IPv6 address (sets IPv6 flag)
        void SetAddress(Ipv6Address addr) {
            _is_ipv6 = true;
            ipv6Addr = addr;
        }

        /// Query whether stored address is IPv6
        bool IsIpv6() const {
            return _is_ipv6;
        }

        /// Get the stored IPv4 address (undefined if IsIpv6()==true)
        Ipv4Address GetIpv4Address() const {
            return ipv4Addr;
        }

        /// Get the stored IPv6 address (undefined if IsIpv6()==false)
        Ipv6Address GetIpv6Address() const {
            return ipv6Addr;
        }

        /// Return the stored address as a generic Address object
        Address GetAddress() const {
            if (_is_ipv6) {
                return Address(ipv6Addr);
            } else {
                return Address(ipv4Addr);
            }
        }

        MpTcpAddressInfo GetAddressInfo() const;
    };

    // mp_fail
    //                        1                   2                   3
    //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //   +---------------+---------------+-------+----------------------+
    //   |     Kind      |   Length=12   |Subtype|      (reserved)      |
    //   +---------------+---------------+-------+----------------------+
    //   |                                                              |
    //   |                 Data Sequence Number (8 octets)              |
    //   |                                                              |
    //   +--------------------------------------------------------------+

    class pkg_mp_fail : public pkg_undefine {
      private:
        uint8_t kind;
        uint8_t length;
        MP_SubType subtype;
        uint64_t drop_dsn;

      public:
        static TypeId GetTypeId();
        pkg_mp_fail();
        pkg_mp_fail(pkg_header header);
        uint32_t Deserialize(Buffer::Iterator it) override;
        Buffer Serialize() override;
        uint8_t CalculateLength() override;
        // ~pkg_mp_fail() override {};
        uint64_t get_fail_dsn();
        void set_fail_dsn(uint64_t dsn);

        static std::string GetName() {
            return "option: MP_FAIL";
        }

        MP_SubType GetSubtype() const override {
            return this->subtype;
        }
    };

    // REMOVE_ADDR
    //                      1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +---------------+---------------+-------+-------+---------------+
    // |     Kind      |Length = 3 + n |Subtype|(resvd)|   Address ID  | ...
    // +---------------+---------------+-------+-------+---------------+
    //                            (followed by n-1 Address IDs, if required)

    class pkg_mp_remove_addr : public pkg_undefine {
      private:
        uint8_t kind;
        uint8_t length;
        MP_SubType subtype;
        std::vector<uint8_t> addresses_id;

      public:
        static TypeId GetTypeId();
        pkg_mp_remove_addr();
        pkg_mp_remove_addr(pkg_header header);

        static std::string GetName() {
            return "option: REMOVE_ADDR";
        }

        void AddAddressId(uint8_t id);
        uint8_t GetAddressCount() const;
        std::vector<uint8_t> GetAddressIDList() const;

        Buffer Serialize() override;
        uint32_t Deserialize(Buffer::Iterator buffer) override;
        uint8_t CalculateLength() override;

        MP_SubType GetSubtype() const override {
            return this->subtype;
        }
    };

    // mp_fastclose
    //                     1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +---------------+---------------+-------+-----------------------+
    // |     Kind      |    Length     |Subtype|      (reserved)       |
    // +---------------+---------------+-------+-----------------------+
    // |                      Option Receiver's Key                    |
    // |                            (64 bits)                          |
    // +---------------------------------------------------------------+

    class pkg_mp_fastclose : public pkg_undefine {
      private:
        uint8_t kind;
        uint8_t length;
        MP_SubType subtype;
        uint64_t receiver_key;

      public:
        static TypeId GetTypeId();
        pkg_mp_fastclose();
        pkg_mp_fastclose(pkg_header header);

        static std::string GetName() {
            return "option: MP_FASTCLOSE";
        }

        Buffer Serialize() override;
        uint32_t Deserialize(Buffer::Iterator buffer) override;
        uint8_t CalculateLength() override;
    };

// mp_tcprst
//                        1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +---------------+---------------+-------+-----------------------+
// |     Kind      |    Length     |Subtype|U|V|W|T|    Reason     |
// +---------------+---------------+-------+-----------------------+

/**
 * flag of mp_tcprst
 * U: reserved; senders must set to 0, and receivers must ignore them
 * V: reserved; senders must set to 0, and receivers must ignore them
 * W: reserved; senders must set to 0, and receivers must ignore them
 * T: (transient error) recipient may attempt to re-establish the subflow over the failed path if
 * T=1
 */
#define MP_TCPRST_FLAG_T 0

    class pkg_mp_tcprst : public pkg_undefine {
      private:
        // uint8_t flags;      // U V W T
        bool flag_U;
        bool flag_V;
        bool flag_W;
        bool transient_error;
        uint8_t kind;
        uint8_t length;
        MP_SubType subtype;
        Reason reason;

      public:
        static TypeId GetTypeId();
        pkg_mp_tcprst();
        pkg_mp_tcprst(pkg_header header);
        ~pkg_mp_tcprst() {};

        static std::string GetName() {
            return "option: MP_TCPRST";
        }

        bool is_transient_error() const {
            return this->transient_error;
        }

        void set_transient_error(bool e = false) {
            this->transient_error = e;
        }

        void set_reason(Reason reason) {
            this->reason = reason;
        }

        Reason get_reason() const {
            return this->reason;
        }

        static std::string GetReasonString(Reason reason) {
            // static const std::unordered_map<Reason, std::string> reasonStr = {
            //     {UNSPECIFIED_ERROR, "Unspecified error"},
            //     {MPTCP_SPECIFIC_ERROR, "MPTCP-specific error"},
            //     {LACK_OF_RESOURCES, "Lack of resources"},
            //     {ADMINISTRATIVELY_PROHIBITED, "Administratively prohibited"},
            //     {TOO_MUCH_OUTSTANDING_DATA, "Too much outstanding data"},
            //     {UNACCEPTABLE_PERFORMANCE, "Unacceptable performance"},
            //     {MIDDLEBOX_INTERFERENCE, "Middlebox interference"}};

            // auto it = reasonStr.find(reason);
            // if (it != reasonStr.end()) {
            //     return it->second;
            // }
            // return "Unknown reason";
            switch (reason) {
            case UNSPECIFIED_ERROR:
                return "Unspecified error";
            case MPTCP_SPECIFIC_ERROR:
                return "MPTCP-specific error";
            case LACK_OF_RESOURCES:
                return "Lack of resources";
            case ADMINISTRATIVELY_PROHIBITED:
                return "Administratively prohibited";
            case TOO_MUCH_OUTSTANDING_DATA:
                return "Too much outstanding data";
            case UNACCEPTABLE_PERFORMANCE:
                return "Unacceptable performance";
            case MIDDLEBOX_INTERFERENCE:
                return "Middlebox interference";
            default:
                return "Unknown reason";
            }
        }

        Buffer Serialize() override;

        uint32_t Deserialize(Buffer::Iterator buffer) override;
        uint8_t CalculateLength() override;

        MP_SubType GetSubtype() const override {
            return this->subtype;
        }
    };

    class DataBuffer {
      public:
        DataBuffer();
        DataBuffer(uint32_t size);
        ~DataBuffer();
        queue<uint8_t> buffer;
        uint32_t bufMaxSize;
        uint32_t Add(uint8_t* buf, uint32_t size);
        uint32_t Add(uint32_t size);
        // uint32_t Retrieve(uint8_t* buf, uint32_t size);
        uint32_t Retrieve(uint32_t size);
        Ptr<Packet> CreatePacket(uint32_t size);
        uint32_t ReadPacket(Ptr<Packet> pkt, uint32_t dataLen);
        bool Empty();
        bool Full();
        bool ClearBuffer();
        uint32_t PendingData();
        uint32_t FreeSpaceSize();
        void SetBufferSize(uint32_t size);
    };

} // namespace ns3
#endif // MP_TCP_TYPEDEFS_H
