#include "ns3/mp-tcp-typedefs.h"

#include "ns3/log.h"
#include "ns3/mp-tcp-socket-base.h"
#include "ns3/simulator.h"
#include "ns3/tcp-header.h"

#include <iostream>

NS_LOG_COMPONENT_DEFINE("MpTcpTypeDefs");

namespace ns3 {
    inline void GetChecksumAlgo(checksum_algo algo) {
        switch (algo) {
        case checksum_algo::HMAC_MURMUR3:

            break;
        case checksum_algo::HMAC_SHA256:
            break;
        case checksum_algo::HMAC_UNKNOW:
        default:
            NS_ABORT_MSG("GetChecksumAlgo(): select algo is not impl!");
            return;
        }
        return;
    }

    Path::Path(shared_ptr<MpTcpAddressInfo> src_addr_info,
               shared_ptr<MpTcpAddressInfo> dest_addr_info) {
        this->src_addr_info = src_addr_info;
        this->dest_addr_info = dest_addr_info;
        this->subflow = CreateObject<MpTcpSubFlow>();
        this->subflow->sAddr = src_addr_info->ipv4Addr;
        this->subflow->sPort = src_addr_info->port;
        this->subflow->dAddr = dest_addr_info->ipv4Addr;
        this->subflow->dPort = dest_addr_info->port;
    }

    Path::Path(shared_ptr<MpTcpAddressInfo> listen_addr_info) {
        NS_LOG_FUNCTION(this << listen_addr_info->ipv4Addr);
        this->src_addr_info = listen_addr_info;
        // this->dest_addr_info = dest_addr_info;
        this->subflow = CreateObject<MpTcpSubFlow>();
        this->subflow->sAddr = src_addr_info->ipv4Addr;
        this->subflow->sPort = src_addr_info->port;
    }

    Path::~Path() {
        src_addr_info->path = nullptr;
        if (dest_addr_info) {
            dest_addr_info->path = nullptr;
        }
    }

    // bool Path::check_sflow_exist() {}
    std::pair<shared_ptr<MpTcpAddressInfo>, shared_ptr<MpTcpAddressInfo>> Path::get_route() const {
        return std::pair<shared_ptr<MpTcpAddressInfo>, shared_ptr<MpTcpAddressInfo>>(
            this->src_addr_info,
            this->dest_addr_info);
    }

    Ptr<MpTcpSubFlow> Path::get_subflow() const {
        return this->subflow;
    }

    void Path::set_subflow(Ptr<MpTcpSubFlow> sf) {
        this->subflow = sf;
    }

    /**
     * @brief Detach the path from its subflow and address info. This is used when a path is
     * removed, and the subflow will be closed. After this operation, the path will be removed from
     * the path manager, and the subflow will be closed by the socket. The address info will be kept
     * in the address pool, but they will not be bound to any path.
     * @todo the subflow should be closed before detaching the path, but the close function is not
     * implemented yet.
     */
    void Path::Detach() {
        // NS_LOG_INFO("Path::Detach -> Detaching path with subflow id ");
        // close the subflow ()
        this->src_addr_info->path = this->dest_addr_info->path = nullptr;
        this->subflow = nullptr;
    }

    void Path::Update(shared_ptr<MpTcpAddressInfo> dest_addr_info) {
        this->dest_addr_info = dest_addr_info;
    }

    ostream& operator<<(ostream& s, const Path& p) {
        if (p.dest_addr_info) {
            s << "Path(" << p.src_addr_info->ipv4Addr << ":" << +p.src_addr_info->port << "->"
              << p.dest_addr_info->ipv4Addr << ":" << +p.dest_addr_info->port << ")";
        } else {
            s << "Path(" << p.src_addr_info->ipv4Addr << ":" << +p.src_addr_info->port
              << "-> NULL)";
        }
        return s;
    }

    /**
     * @brief Add an address to the address pool. The address will be added to the local or remote
     * address
     *
     * @param type the type of the address, local or remote
     * @param addrInfo the address info to be added, which contains the address id, the ipv4
     * address and the mask. The address id is defined by rfc 8684, and it is used to identify the
     * address in the path manager.
     * @return int return the address in uint8_t if the address is added successfully, return -1 if
     * the address type is invalid.
     */
    int PathManager::add_address(addr_t type, MpTcpAddressInfo addrInfo) {
        int addrId{};
        if ((addrId = this->is_addr_exist(type, addrInfo.ipv4Addr)) != -1) {
            NS_LOG_WARN(((type == local) ? "local" : "remote")
                        << " addr_id: " << +addrId << " is already exist");
            return addrId;
        }
        switch (type) {
        case local:
            addrId = localAddrs.size();
            this->localAddrs[addrId] = make_shared<MpTcpAddressInfo>(addrInfo);
            this->localAddrs[addrId]->addrID = addrId;
            // if (!this->localAddrs[addrId]->port) {
            // }
            break;
        case remote:
            addrId = remoteAddrs.size();
            this->remoteAddrs[addrId] = make_shared<MpTcpAddressInfo>(addrInfo);
            this->remoteAddrs[addrId]->addrID = addrId;
            break;
        default:
            NS_LOG_WARN("PathManager::add_address -> invalid address type !");
            return -1;
        }
        NS_LOG_DEBUG("add " << +addrId << "th address to " << (type ? "remote" : "local")
                            << "address with addr: " << addrInfo.ipv4Addr << ":" << addrInfo.port);
        return addrId;
    }

    /**
     * @brief
     *
     * @param type
     * @param addr
     * @return int addr_id(uint8_t) if found in known ip, else return -1
     */
    int PathManager::is_addr_exist(addr_t type, Ipv4Address addr) {
        map<uint8_t, shared_ptr<MpTcpAddressInfo>>* addresses = nullptr;
        switch (type) {
        case local:
            addresses = &this->localAddrs;
            break;
        case remote:
            addresses = &this->remoteAddrs;
            break;
        default:
            NS_ABORT_MSG("is_addr_exist(): ?");
            break;
        }
        for (auto it : *addresses) {
            if (it.second->ipv4Addr == addr) {
                NS_LOG_DEBUG("is_addr_exist(): found addr " << it.second->ipv4Addr
                                                            << " in know address.");
                return it.second->addrID;
            }
        }
        return -1;
    }

    void PathManager::set_max_subflow(uint8_t max_subflow) {
        NS_LOG_INFO("PathManager: reset_maxsubflow to " << +max_subflow);
        this->maxSubflow = max_subflow;
    }

    /**
     * @brief remove an address from the address pool. If the address is used by a path, the path
     * will be detached and removed as well.
     *
     * @param type the type of the address, local or remote
     * @param addr_id the address id of the address to be removed, which is defined by rfc 8684
     */
    void PathManager::remove_address(addr_t type, uint8_t addr_id) {
        if (type == local) {
            if (this->localAddrs[addr_id] != nullptr) {
            }
            this->localAddrs.erase(addr_id);
        } else if (type == remote) {
            this->remoteAddrs.erase(addr_id);
        } else {
            NS_LOG_WARN("PathManager::remove_address -> invalid address type !");
        }
    }

    /**
     * @brief create new subflow and bind the flow to localAddress and remoteAddress.
     *
     * @param src_id src_id of the local address, which is defined by rfc 8684
     * @param dest_id same as src_id but remote
     * @return size_t the route id of the new path, which is also the subflow id of the new subflow.
     * If the path already exists, return the existing path's route id.
     */
    int PathManager::create_path(uint8_t src_id,
                                 uint8_t dest_id,
                                 Ptr<NetDevice> NetDev_of_src,
                                 Ptr<TcpL4Protocol> tcp) {
        if (this->links.size() >= this->maxSubflow) {
            NS_LOG_WARN("PathManager::add_path -> reach max subflow " << +this->maxSubflow);
            return -1;
        }
        if (this->localAddrs[src_id]->path != nullptr) {
            NS_LOG_INFO("src " << +src_id << " path is already exist");
            return this->localAddrs[src_id]->path->get_subflow()->routeId;
        }
        if (this->remoteAddrs[dest_id]->path != nullptr) {
            NS_LOG_INFO("dest " << +dest_id << " path is already exist");
            return this->remoteAddrs[dest_id]->path->get_subflow()->routeId;
        }
        uint8_t routeId = this->gen_route_id();
        if (this->links.find(routeId) != this->links.end()) {
            NS_LOG_WARN("PathManager::add_path -> path already exist !");
            return routeId;
        }
        auto src_addr_info = this->localAddrs[src_id];
        auto dest_addr_info = this->remoteAddrs[dest_id];
        auto path = this->localAddrs[src_id]->path = this->remoteAddrs[dest_id]->path =
            this->links[routeId] = make_shared<Path>(src_addr_info, dest_addr_info);
        // Ptr<MpTcpSubFlow> subflow = CreateObject<MpTcpSubFlow>();
        auto subflow = path->get_subflow();
        // path->set_subflow(subflow);
        Ipv4EndPoint* endpoint;
        if (src_addr_info->port) {
            endpoint = tcp->Allocate(NetDev_of_src, src_addr_info->ipv4Addr, src_addr_info->port);
        } else {
            endpoint = tcp->Allocate(src_addr_info->ipv4Addr); // dont need netdev?
            src_addr_info->port = endpoint->GetLocalPort();
            NS_LOG_DEBUG("create_path(): allocating new port: " << +src_addr_info->port);
        }
        NS_ASSERT_MSG(endpoint != nullptr,
                      "create_path(): ip " << src_addr_info->ipv4Addr << ":" << src_addr_info->port
                                           << " fail to allocate.");
        NS_LOG_DEBUG("create_path(): allocating local ip: " << endpoint->GetLocalAddress() << ":"
                                                            << endpoint->GetLocalPort());
        subflow->m_endPoint = endpoint;
        subflow->sAddr = src_addr_info->ipv4Addr;
        subflow->sPort = src_addr_info->port; // reassign
        // subflow->dAddr = dest_addr_info->ipv4Addr;
        // subflow->dPort = dest_addr_info->port;
        subflow->routeId = routeId;
        subflow->state = TcpSocket::TcpStates_t::LISTEN;
        subflow->cnCount = subflow->cnRetries;

        NS_ASSERT(this->links[routeId] != nullptr);
        // NS_LOG_INFO("path(" << hex << this->localAddrs[0] << ") ptr: " << std::hex
        //                     << this->localAddrs[0]->path);
        NS_LOG_DEBUG("new " << +routeId << "th links(subflow) as " << src_addr_info->ipv4Addr
                            << " -> " << dest_addr_info->ipv4Addr);
        return routeId;
    }

    int PathManager::bind(uint8_t dest_id, Ptr<NetDevice> NetDev_of_src, Ptr<TcpL4Protocol> tcp) {
        if (this->links.size() >= this->maxSubflow) {
            NS_LOG_WARN("PathManager::bind -> reach max subflow " << +this->maxSubflow);
            return -1;
        }

        // 檢查 local address 是否存在
        if (this->localAddrs.find(dest_id) == this->localAddrs.end()) {
            NS_LOG_WARN("PathManager::bind -> local addr not found");
            return -1;
        }

        auto src_addr_info = this->localAddrs[dest_id];
        if (src_addr_info->path != nullptr) {
            NS_LOG_INFO("bind(): addr " << +dest_id << " already bound");
            return src_addr_info->path->get_subflow()->routeId;
        }

        uint8_t routeId = this->gen_route_id();
        if (this->links.find(routeId) != this->links.end()) {
            NS_LOG_WARN("PathManager::bind -> route already exists !");
            return routeId;
        }

        // ⚠️ bind 階段沒有 remote，先給 nullptr 或 dummy
        auto path = this->links[routeId] = make_shared<Path>(src_addr_info);
        src_addr_info->path = path;

        Ptr<MpTcpSubFlow> subflow = CreateObject<MpTcpSubFlow>();
        path->set_subflow(subflow);

        Ipv4EndPoint* endpoint;
        if (src_addr_info->port) {
            endpoint = tcp->Allocate(NetDev_of_src, src_addr_info->ipv4Addr, src_addr_info->port);
        } else {
            endpoint = tcp->Allocate(src_addr_info->ipv4Addr);
            src_addr_info->port = endpoint->GetLocalPort();
            NS_LOG_DEBUG("bind(): allocating new port: " << +src_addr_info->port);
        }
        NS_ASSERT_MSG(endpoint != nullptr,
                      "bind(): ip " << src_addr_info->ipv4Addr << ":" << +src_addr_info->port
                                    << " fail to allocate.");

        // 設定 subflow（被動端）
        // subflow->m_endPoint = endpoint;
        subflow->sAddr = src_addr_info->ipv4Addr;
        subflow->sPort = src_addr_info->port;
        subflow->m_endPoint = endpoint;

        // 尚未知道 remote
        subflow->dAddr = Ipv4Address::GetAny();
        subflow->dPort = 0;

        subflow->routeId = routeId;
        subflow->state = TcpSocket::TcpStates_t::LISTEN;
        subflow->cnCount = subflow->cnRetries;

        NS_LOG_DEBUG("bind(): new LISTEN subflow " << +routeId << " on " << subflow->sAddr << ":"
                                                   << +subflow->sPort);

        return routeId;
    }

    bool PathManager::update_remote_addr(uint8_t route_id, uint8_t remote_id) {
        auto route = this->links[route_id];
        auto dest_addr_info = this->remoteAddrs[remote_id];
        if (route == nullptr) {
            NS_LOG_DEBUG("route is not exist!");
            return true;
        }
        if (dest_addr_info == nullptr) {
            NS_LOG_DEBUG("dest addr is not exist");
            return true;
        }
        route->Update(dest_addr_info);
        dest_addr_info->path = route;
        auto subflow = route->get_subflow();
        NS_LOG_INFO("update sFlow[" << +route_id << "] with remote address"
                                    << dest_addr_info->ipv4Addr << ":" << dest_addr_info->port);
        subflow->dAddr = dest_addr_info->ipv4Addr;
        subflow->dPort = dest_addr_info->port;
        return false;
    }

    shared_ptr<Path> PathManager::get_path_from_addr(uint8_t addr_id) const {
        for (const auto& it : this->links) {
            if (it.second->get_route().first->addrID == addr_id ||
                it.second->get_route().second->addrID == addr_id) {
                return it.second;
            }
        }
        NS_LOG_WARN("PathManager::get_path_from_addr -> path not exist !");
        return nullptr;
    }

    void PathManager::remove_path(uint8_t subflow_id) {
        NS_LOG_FUNCTION(this);
        // for (auto& it : this->links) {
        //     if (it.first == subflow_id) {
        //         auto path = it.second;
        //         auto ip = path->get_route();
        //         this->localAddrs[ip.first->addrID]->path =
        //             this->remoteAddrs[ip.second->addrID]->path = nullptr;
        //         this->links.erase(it.first);
        //         // NS_LOG_()
        //         return;
        //     }
        // }
        std::map<uint8_t, std::shared_ptr<ns3::Path>>::iterator it;
        if ((it = this->links.find(subflow_id)) != this->links.end()) {
            auto path = it->second;
            auto ip = path->get_route();
            this->localAddrs[ip.first->addrID]->path = this->remoteAddrs[ip.second->addrID]->path =
                nullptr;
            this->links.erase(it->first);
            NS_LOG_DEBUG("remove one link");
        }
    }

    shared_ptr<MpTcpAddressInfo> PathManager::get_address_info(addr_t type, uint8_t addr_id) const {
        if (type == local) {
            auto it = this->localAddrs.find(addr_id);
            if (it != this->localAddrs.end()) {
                return it->second;
            }
        } else if (type == remote) {
            auto it = this->remoteAddrs.find(addr_id);
            if (it != this->remoteAddrs.end()) {
                return it->second;
            }
        } else {
            NS_LOG_WARN("PathManager::get_address_info -> invalid address type !");
            return nullptr;
        }
        NS_LOG_WARN("PathManager::get_address_info -> address not exist !");
        return nullptr;
    }

    Ptr<MpTcpSubFlow> PathManager::get_subflow(uint8_t sFlowId) const {
        auto it = this->links.find(sFlowId);
        if (it != this->links.end()) {
            return it->second->get_subflow();
        }
        NS_LOG_WARN("PathManager::get_subflow -> path not exist !");
        return nullptr;
    }

    uint8_t PathManager::gen_route_id() {
        return this->links.size();
    }

    DSNMapping::DSNMapping() {
        subflowIndex = 255;
        acknowledgement = 0;
        dataSeqNumber = 0;
        dataLevelLength = 0;
        subflowSeqNumber = 0;
        dupAckCount = 0;
        // packet = 0;
    }

    DSNMapping::DSNMapping(uint8_t sFlowIdx,
                           uint64_t dSeqNum,
                           uint16_t dLvlLen,
                           uint32_t sflowSeqNum,
                           uint32_t ack /*, Ptr<Packet> pkt*/) {
        subflowIndex = sFlowIdx;
        dataSeqNumber = dSeqNum;
        dataLevelLength = dLvlLen;
        subflowSeqNumber = sflowSeqNum;
        acknowledgement = ack;
        dupAckCount = 0;
        // packet = new uint8_t[dLvlLen];
        // pkt->CopyData(packet, dLvlLen);
    }

    /*
     DSNMapping::DSNMapping (const DSNMapping &res)
     {
     subflowIndex     = res.subflowIndex;
     acknowledgement  = res.acknowledgement;
     dataSeqNumber    = res.dataSeqNumber;
     dataLevelLength  = res.dataLevelLength;
     subflowSeqNumber = res.subflowSeqNumber;
     dupAckCount      = res.dupAckCount;
     packet           = res.packet;
     original         = false;
     }
     */
    DSNMapping::~DSNMapping() {
        dataSeqNumber = 0;
        dataLevelLength = 0;
        subflowSeqNumber = 0;
        dupAckCount = 0;
        //  if (packet != 0)
        // delete[] packet;
        // packet = 0;
    }

    bool DSNMapping::operator<(const DSNMapping& rhs) const {
        return this->dataSeqNumber < rhs.dataSeqNumber;
    }

    DataBuffer::DataBuffer() {
        bufMaxSize = 0;
    }

    DataBuffer::DataBuffer(uint32_t size) {
        bufMaxSize = size;
    }

    DataBuffer::~DataBuffer() {
        bufMaxSize = 0;
    }

    uint32_t DataBuffer::Add(uint32_t size) {
        // read data from buf and insert it into the DataBuffer instance
        NS_LOG_FUNCTION(this << (int)size << (int)(bufMaxSize - (uint32_t)buffer.size()));
        uint32_t toWrite = std::min(size, (bufMaxSize - (uint32_t)buffer.size()));
        if (buffer.empty() == true) {
            NS_LOG_INFO("DataBuffer::Add -> buffer is empty !");
        } else {
            NS_LOG_INFO("DataBuffer::Add -> buffer was not empty !");
        }

        uint32_t qty = 0;

        while (qty < toWrite) {
            // buffer.push(buf[qty]);
            buffer.push((uint8_t)qty);
            qty++;
        }
        NS_LOG_INFO("DataBuffer::Add -> amount of data = " << qty);
        NS_LOG_INFO(
            "DataBuffer::Add -> freeSpace Size = " << (bufMaxSize - (uint32_t)buffer.size()));
        return qty;
    }

    uint32_t DataBuffer::Add(uint8_t* buf, uint32_t size) {
        // read data from buf and insert it into the DataBuffer instance
        NS_ASSERT_MSG((buf != nullptr), "DataBuffer::Add -> input buffer is null !");
        NS_LOG_FUNCTION(this << (int)size << (int)(bufMaxSize - (uint32_t)buffer.size()));
        uint32_t toWrite = std::min(size, (bufMaxSize - (uint32_t)buffer.size()));
        if (buffer.empty() == true) {
            NS_LOG_INFO("DataBuffer::Add -> buffer is empty !");
        } else {
            NS_LOG_INFO("DataBuffer::Add -> buffer was not empty !");
        }

        NS_LOG_INFO("curr buf size: " << buffer.size());
        uint32_t qty = 0;

        while (qty < toWrite) {
            buffer.push(buf[qty]);
            // buffer.push((uint8_t)qty);
            qty++;
        }
        NS_LOG_INFO("DataBuffer::Add -> amount of data = " << qty);
        NS_LOG_INFO(
            "DataBuffer::Add -> freeSpace Size = " << (bufMaxSize - (uint32_t)buffer.size()));
        return qty;
    }

#ifdef OLD
    uint32_t DataBuffer::Add(uint8_t* buf, uint32_t size) {
        // read data from buf and insert it into the DataBuffer instance
        NS_LOG_FUNCTION(this << (int)size << (int)(bufMaxSize - (uint32_t)buffer.size()));
        uint32_t toWrite = std::min(size, (bufMaxSize - (uint32_t)buffer.size()));
        if (buffer.empty() == true) {
            NS_LOG_INFO("DataBuffer::Add -> buffer is empty !");
        } else {
            NS_LOG_INFO("DataBuffer::Add -> buffer was not empty !");
        }

        uint32_t qty = 0;

        while (qty < toWrite) {
            // buffer.push(buf[qty]);
            buffer.push((uint8_t)qty);
            qty++;
        }
        NS_LOG_INFO("DataBuffer::Add -> amount of data = " << qty);
        NS_LOG_INFO(
            "DataBuffer::Add -> freeSpace Size = " << (bufMaxSize - (uint32_t)buffer.size()));
        return qty;
    }
#endif

    uint32_t DataBuffer::Retrieve(uint32_t size) {
        NS_LOG_FUNCTION(this << (int)size << (int)(bufMaxSize - (uint32_t)buffer.size()));
        uint32_t quantity = std::min(size, (uint32_t)buffer.size());
        if (quantity == 0) {
            NS_LOG_INFO("DataBuffer::Retrieve -> No data to read from buffer reception !");
            return 0;
        }

        for (uint32_t i = 0; i < quantity; i++) {
            // buf[i] = buffer.front();
            buffer.pop();
        }

        NS_LOG_INFO("DataBuffer::Retrieve -> freeSpaceSize == " << bufMaxSize -
                                                                       (uint32_t)buffer.size());
        return quantity;
    }

    // uint32_t
    // DataBuffer::Retrieve(uint8_t* buf, uint32_t size)
    //{
    //   NS_LOG_FUNCTION (this << (int) size << (int) (bufMaxSize - (uint32_t) buffer.size()) );
    //   uint32_t quantity = std::min(size, (uint32_t) buffer.size());
    //   if (quantity == 0)
    //     {
    //       NS_LOG_INFO("DataBuffer::Retrieve -> No data to read from buffer reception !");
    //       return 0;
    //     }
    //
    //   for (uint32_t i = 0; i < quantity; i++)
    //     {
    //       buf[i] = buffer.front();
    //       buffer.pop();
    //     }
    //
    //   NS_LOG_INFO("DataBuffer::Retrieve -> freeSpaceSize == "<< bufMaxSize - (uint32_t)
    //   buffer.size()
    //   ); return quantity;
    // }

    Ptr<Packet> DataBuffer::CreatePacket(uint32_t size) {
        NS_LOG_FUNCTION(this << (int)size << (int)(bufMaxSize - (uint32_t)buffer.size()));
        uint32_t quantity = std::min(size, (uint32_t)buffer.size());
        if (quantity == 0) {
            NS_LOG_INFO("DataBuffer::CreatePacket -> No data ready for sending !");
            return 0;
        }
        // Copy from front of Buffer to a new uint8_t array pointer
        // uint8_t *ptrBuffer = new uint8_t[quantity];
        for (uint32_t i = 0; i < quantity; i++) {
            // ptrBuffer[i] = buffer.front();
            buffer.pop();
        }
        // Create packet from a data pointer and its size
        // Ptr<Packet> pkt = new Packet(ptrBuffer, quantity);
        // Ptr<Packet> pkt = Create<Packet>(ptrBuffer, quantity);
        Ptr<Packet> pkt = Create<Packet>(quantity);
        // delete[] ptrBuffer;
        // ptrBuffer = 0; // MKS

        NS_LOG_INFO("DataBuffer::CreatePacket -> freeSpaceSize == " << bufMaxSize -
                                                                           (uint32_t)buffer.size());
        return pkt;
    }

    uint32_t DataBuffer::ReadPacket(Ptr<Packet> pkt, uint32_t dataLen) {
        NS_LOG_INFO(this << (int)(bufMaxSize - (uint32_t)buffer.size()));

        uint32_t toWrite = std::min(dataLen, (bufMaxSize - (uint32_t)buffer.size()));

        // uint8_t *ptrBuffer = new uint8_t[toWrite];
        // pkt->CopyData(ptrBuffer, toWrite);

        for (uint32_t i = 0; i < toWrite; i++) {
            buffer.push(0);
        }
        // buffer.push(ptrBuffer[i]);

        // delete[] ptrBuffer;
        // ptrBuffer = 0; // MKS

        NS_LOG_INFO("DataBuffer::ReadPacket -> data   readed == " << toWrite);
        NS_LOG_INFO("DataBuffer::ReadPacket -> freeSpaceSize == " << bufMaxSize -
                                                                         (uint32_t)buffer.size());
        return toWrite;
    }

    uint32_t DataBuffer::PendingData() {
        return ((uint32_t)buffer.size());
    }

    bool DataBuffer::ClearBuffer() {
        while (!buffer.empty()) {
            buffer.pop();
        }
        NS_ASSERT(buffer.empty());
        return true;
    }

    uint32_t DataBuffer::FreeSpaceSize() {
        return (bufMaxSize - (uint32_t)buffer.size());
    }

    bool DataBuffer::Empty() {
        return buffer.empty(); // ( freeSpaceSize == bufMaxSize );
    }

    bool DataBuffer::Full() {
        return (bufMaxSize == (uint32_t)buffer.size()); //( freeSpaceSize == 0 );
    }

    void DataBuffer::SetBufferSize(uint32_t size) {
        bufMaxSize = size;
    }

    MpTcpAddressInfo::MpTcpAddressInfo()
        : addrID(0),
          ipv4Addr(Ipv4Address::GetZero()),
          mask(Ipv4Mask::GetZero()),
          acked(false),
          path(nullptr) {
    }

    MpTcpAddressInfo::~MpTcpAddressInfo() {
        addrID = 0;
        ipv4Addr = Ipv4Address::GetZero();
    }

    pkg_undefine::pkg_undefine()
        : kind(TcpOptionMptcp::Kind::MULTIPATH_TCP),
          length(0xff),
          subtype(MP_SubType::MP_EXPERIMENT) {
    }

    pkg_undefine::pkg_undefine(pkg_header header)
        : kind(header.kind),
          length(header.length),
          subtype(header.subtype) {
    }

    Buffer pkg_undefine::Serialize() {
        Buffer buf;
        auto i = buf.Begin();
        i.WriteU8(this->kind);
        i.WriteU8(this->length);
        uint8_t flag = 0;
        PKG_SETLOWU8(flag, MP_SubType::MP_EXPERIMENT);
        i.WriteU8(flag);
        return buf;
    }

    uint32_t pkg_undefine::Deserialize(Buffer::Iterator it) {
        this->kind = it.ReadU8();
        this->length = it.ReadU8();
        this->subtype = PKG_GETSUBTYPEU8(it.PeekU8());
        if (length < 3) {
            return 0;
        }
        // auto buf = this->_data.Begin();
        // buf.WriteU8(PKG_GETHIGHU8(it.ReadU8()));
        // buf.WriteU(it.ReadU(this->length - 3), this->length - 3);
        return 4;
    }

    uint8_t pkg_undefine::CalculateLength() {
        auto buf_size = static_cast<uint8_t>(this->_data.GetSize());
        buf_size = buf_size ? buf_size - 1 : 0;
        return 3 + buf_size;
    }

    TypeId pkg_undefine::GetTypeId() {
        static auto tid = TypeId("ns3::pkg_undefine").SetParent<Object>().SetGroupName("Internet");
        // NS_ABORT_IF(true);
        return tid;
    }

    TcpOptionMptcp::TcpOptionMptcp() {
    }

    TcpOptionMptcp::TcpOptionMptcp(MP_SubType subtype) {
        switch (subtype) {
        case MP_SubType::MP_CAPABLE:
            this->pkg = CreateObject<pkg_mp_capable>();
            break;
        case MP_SubType::MP_JOIN:
            this->pkg = CreateObject<pkg_mp_join>();
            break;
        case MP_SubType::DSS:
            this->pkg = CreateObject<pkg_mp_dss>();
            break;
        case MP_SubType::MP_PRIO:
            this->pkg = CreateObject<pkg_mp_prio>();
            break;
        case MP_SubType::ADD_ADDR:
            this->pkg = CreateObject<pkg_mp_add_addr>();
            break;
        case MP_SubType::MP_FAIL:
            this->pkg = CreateObject<pkg_mp_fail>();
            break;
        case MP_SubType::MP_FASTCLOSE:
            this->pkg = CreateObject<pkg_mp_fastclose>();
            break;
        case MP_SubType::MP_TCPRST:
            this->pkg = CreateObject<pkg_mp_tcprst>();
            break;
        case MP_SubType::MP_EXPERIMENT:
        default:
            this->pkg = CreateObject<pkg_undefine>();
            break;
        }
    }

    NS_OBJECT_ENSURE_REGISTERED(TcpOptionMptcp);

    TypeId TcpOptionMptcp::GetTypeId() {
        static auto tid =
            TypeId("ns3::TcpOptionMptcp").SetParent<TcpOption>().AddConstructor<TcpOptionMptcp>();
        //    .AddAttribute("Subtype",
        //                  "MPTCP Subtype to initialize the package",
        //                  EnumValue(MP_EXPERIMENT),
        //                  MakeEnumAccessor(MP_SubType),
        //                  MakeEnumChecker();
        //  MakeEnumAccessor<MP_SubType>(&TcpOptionMptcp::SetSubType),
        //  MakeEnumChecker(MP_CAPABLE,
        //                  "MP_CAPABLE",
        //                  MP_JOIN,
        //                  "MP_JOIN",
        //                  DSS,
        //                  "DSS",
        //                  ADD_ADDR,
        //                  "ADD_ADDR",
        //                  REMOVE_ADDR,
        //                  "REMOVE_ADDR",
        //                  MP_PRIO,
        //                  "MP_PRIO",
        //                  MP_FAIL,
        //                  "MP_FAIL",
        //                  MP_FASTCLOSE,
        //                  "MP_FASTCLOSE",
        //                  MP_TCPRST,
        //                  "MP_TRCPST",
        //                  MP_EXPERIMENT,
        //                  "MP_EXPERIMENT"));
        return tid;
    }

    void TcpOptionMptcp::SetSubType(MP_SubType subtype) {
        // 這裡實現你的邏輯：指定 subtype 時自動建立空封包
        // this->pkg = CreateObject<pkg_undefine>(subtype);
        switch (subtype) {
        case MP_CAPABLE:
            pkg = CreateObject<pkg_mp_capable>();
            break;

        case MP_JOIN:
            pkg = CreateObject<pkg_mp_join>();
            break;

        default:
            pkg = CreateObject<pkg_undefine>();
            break;
        }
    }

    // 如果 pkg_undefine 也是 ns3::Object，則建議用：
    // this->pkg = CreateObject<pkg_undefine> ();
    // this->pkg->SetType(subtype);
    // MP_SubType TcpOptionMptcp::GetSubType() const {
    //     NS_ASSERT(this->pkg == nullptr);
    //     return this->pkg->get_subtype();
    // }
    // TypeId TcpOptionMptcp::GetTypeId() {
    //     static TypeId tid = TypeId("ns3::TcpOptionMptcp")
    //         .SetParent<TcpOption>()
    //         .SetGroupName("Internet")
    //         .AddConstructor<TcpOptionMptcp>();
    //     return tid;
    // }
    uint8_t TcpOptionMptcp::GetKind() const {
        return TcpOption::MULTIPATH_TCP;
    }

    Ptr<pkg_undefine> TcpOptionMptcp::GetPackage() {
        return this->pkg;
    }

    Ptr<const pkg_undefine> TcpOptionMptcp::GetPackage() const {
        return this->pkg;
    }

    void TcpOptionMptcp::Serialize(Buffer::Iterator buf) const {
        auto _buf = this->pkg->Serialize();
        // auto i = _buf.Begin();
        buf.Write(_buf.Begin(), _buf.End());
    }

    bool TcpOptionMptcp::is_known_subtype(uint8_t subtype) const {
        bool rtn = false;
        NS_LOG_INFO("is_known_subtype(): receiverd subtype: "
                    << GetSubtypeName(static_cast<MP_SubType>(subtype)));
        switch (subtype) {
        case MP_SubType::MP_CAPABLE:   // Multipath Capable
        case MP_SubType::MP_JOIN:      // Join Connection
        case MP_SubType::DSS:          // Data Sequence Signal
        case MP_SubType::ADD_ADDR:     // Add Address
        case MP_SubType::REMOVE_ADDR:  // Remove Address
        case MP_SubType::MP_PRIO:      // Change Subflow Priority
        case MP_SubType::MP_FAIL:      // Fallback
        case MP_SubType::MP_FASTCLOSE: // Fast Close
        case MP_SubType::MP_TCPRST:    // Subflow Reset
            rtn = true;
            break;
        case MP_SubType::MP_EXPERIMENT:
        default:
            rtn = false;
            break;
        }
        return rtn;
    }

    uint32_t TcpOptionMptcp::Deserialize(Buffer::Iterator start) {
        auto i = start;
        pkg_header header;
        header.kind = i.ReadU8();
        ASSERT((header.kind) != Kind::MULTIPATH_TCP,
               "TcpOptionMptcp::Deserialize: here should not be other option pkg here!");
        header.length = i.ReadU8();
        header.subtype = PKG_GETSUBTYPEU8(i.PeekU8());
        TEST(!(this->is_known_subtype(header.subtype)), "received unknow subtype pkg", return 1;);
        // NS_LOG_INFO("get subtype: " << header.subtype);
        switch (header.subtype) {
        case MP_SubType::MP_CAPABLE:
            // pkg_mp_capable* pkg = new pkg_mp_capable(pkg_header);
            // this->_pkg = helper.create_object<pkg_mp_capable>(pkg_header);
            this->pkg = CreateObject<pkg_mp_capable>(header);
            // this->pkg->Deserialize(i);
            break;
        case MP_SubType::MP_JOIN:
            // pkg_mp_capable* pkg = new pkg_mp_join_synack(pkg_header);
            this->pkg = CreateObject<pkg_mp_join>(header);
            // this->pkg->Deserialize(i);
            break;
        case MP_SubType::DSS:
            this->pkg = CreateObject<pkg_mp_dss>(header);
            // this->pkg->Deserialize(i);
            break;
        case MP_SubType::ADD_ADDR:
            this->pkg = CreateObject<pkg_mp_add_addr>(header);
            break;
        case MP_SubType::REMOVE_ADDR:
            this->pkg = CreateObject<pkg_mp_remove_addr>(header);
            break;
        case MP_SubType::MP_PRIO:
            this->pkg = CreateObject<pkg_mp_prio>(header);
            break;
        case MP_SubType::MP_FAIL:
            this->pkg = CreateObject<pkg_mp_fail>(header);
            break;
        case MP_SubType::MP_FASTCLOSE:
            this->pkg = CreateObject<pkg_mp_fastclose>(header);
            break;
        case MP_SubType::MP_TCPRST:
            this->pkg = CreateObject<pkg_mp_tcprst>(header);
            break;
        case MP_SubType::MP_EXPERIMENT:
        default:
            this->pkg = CreateObject<pkg_undefine>(header);
            // this->pkg = nullptr;
        }
        if (this->pkg == nullptr) {
            return 1;
        }
        return this->pkg->Deserialize(i);
    }

    pkg_mp_capable::pkg_mp_capable()
        : kind(TcpOptionMptcp::Kind::MULTIPATH_TCP),
          length(0xff),
          subtype(MP_SubType::MP_CAPABLE),
          sender_key(0x0),
          receiver_key(0x0),
          data_level_length(0x0),
          checksum(0),
          _is_checksum_require(false),
          _no_more_subflow(false),
          _with_first_data(false) {
    }

    pkg_mp_capable::pkg_mp_capable(pkg_header header)
        : kind(header.kind),
          length(header.length),
          subtype(header.subtype),
          version(1),
          sender_key(0x0),
          receiver_key(0x0),
          data_level_length(0x0),
          checksum(0),
          _is_checksum_require(false),
          _no_more_subflow(false),
          _with_first_data(false) {
    }

    Buffer pkg_mp_capable::Serialize() {
        Buffer rtn;
        this->length = CalculateLength();
        rtn.AddAtEnd(this->length);
        auto i = rtn.Begin();
        i.WriteU8(TcpOptionMptcp::Kind::MULTIPATH_TCP);
        i.WriteU8(this->length);
        uint8_t tmp;
        PKG_SETSUBTYPEU8(tmp, MP_CAPABLE);
        PKG_SETLOWU8(tmp, this->version);
        i.WriteU8(tmp);
        tmp = 0U;
        if (this->_is_checksum_require) {
            set_bit8(tmp, MP_CAPABLE_FLAG_A);
        }
        // clear_bit8(tmp, MP_CAPABLE_FLAG_B);
        if (this->_no_more_subflow) {
            set_bit8(tmp, MP_CAPABLE_FLAG_C);
        }
        // set_bit8(tmp, this->_checksum_algo);
        tmp |= this->_checksum_algo;
        i.WriteU8(tmp);
        if (this->sender_key) {
            i.WriteHtonU64(this->sender_key);
        }
        if (this->receiver_key) {
            i.WriteHtonU64(this->receiver_key);
        }
        if (this->_with_first_data) {
            i.WriteHtonU16(this->data_level_length);
            if (this->_is_checksum_require) {
                i.WriteHtonU16(this->checksum);
            }
        }
        // NS_LOG_INFO("actually use size of buf: " << rtn.GetSize());
        return rtn;
    }

    uint32_t pkg_mp_capable::Deserialize(Buffer::Iterator buf) {
        auto tmp = buf.ReadU8();
        this->version = PKG_GETLOWU8(tmp);
        // printf("subtype in iterator: %hhu, subtype from inheritence\n", PKG_GETSUBTYPEU8(tmp));
        auto flag = buf.ReadU8();
        this->_is_checksum_require = get_bit8(flag, MP_CAPABLE_FLAG_A);
        this->preserved = get_bit8(flag, MP_CAPABLE_FLAG_B);
        this->_no_more_subflow = get_bit8(flag, MP_CAPABLE_FLAG_C);
        // this->_checksum_algo = get_bit8(flag, checksum_algo::HMAC_SHA256);
        if (!(flag & 31U)) {
            this->_checksum_algo = checksum_algo::HMAC_UNKNOW;
        } else {
            this->_checksum_algo = static_cast<checksum_algo>(flag & 31U);
        }
        // MpTcpHashFactory factory;
        // this->checksum_algo=factory.Create(flag & 31U)
        if (this->length > 4) {
            this->sender_key = buf.ReadNtohU64();
        }
        if (this->length > 12) {
            this->receiver_key = buf.ReadNtohU64();
        }
        if (this->length == 22) {
            this->data_level_length = buf.ReadNtohU16();
        }
        if (this->_is_checksum_require && (this->length == 24)) {
            this->checksum = buf.ReadNtohU16();
        }
        return this->CalculateLength();
    }

    uint8_t pkg_mp_capable::CalculateLength() {
        size_t size = 4;
        if (sender_key != 0) {
            size += 8;
        }
        if (receiver_key != 0) {
            size += 8;
        }
        if ((size >= 20) && this->_with_first_data) {
            size += 2;
            if (this->_is_checksum_require) {
                size += 2;
            }
        }
        return size;
    }

    TypeId pkg_mp_capable::GetTypeId() {
        static auto tid = TypeId("pkg_mp_capable")
                              .SetParent<pkg_undefine>()
                              .SetGroupName("Internet")
                              .AddConstructor<pkg_mp_capable>();
        return tid;
    }

    TypeId pkg_mp_join::GetTypeId() {
        static TypeId tid = TypeId("pkg_mp_join")
                                .SetParent<pkg_undefine>()
                                .SetGroupName("Internet")
                                .AddConstructor<pkg_mp_join>();
        return tid;
    }

    pkg_mp_join::pkg_mp_join()
        : kind(TcpOptionMptcp::Kind::MULTIPATH_TCP),
          length(0),
          subtype(MP_JOIN),
          state(JOIN_NONE),
          backup(false),
          address_id(0),
          receiver_token(0),
          sender_random(0),
          truncated_hmac_64(0) { // l953
        memset(truncated_hmac_160, 0, 20);
    }

    pkg_mp_join::pkg_mp_join(pkg_header header)
        : kind(header.kind),
          length(header.length),
          subtype(header.subtype),
          state(JOIN_NONE),
          backup(false),
          address_id(0),
          receiver_token(0),
          sender_random(0),
          truncated_hmac_64(0) {
        memset(truncated_hmac_160, 0, 20);
    }

    // bool pkg_mp_join::check(uint32_t key) const {
    //     auto fake_token = this->hash->GetChecksum<uint32_t>(key);
    //     return (fake_token == this->receiver_token);
    // }

    Buffer pkg_mp_join::Serialize() {
        Buffer buf;
        this->length = CalculateLength();
        buf.AddAtEnd(this->length);
        auto i = buf.Begin();

        i.WriteU8(TcpOptionMptcp::Kind::MULTIPATH_TCP);
        i.WriteU8(this->length);

        uint8_t tmp = 0;
        PKG_SETSUBTYPEU8(tmp, subtype);

        if (state == JOIN_SYN || state == JOIN_SYNACK) {
            if (backup) {
                set_bit8(tmp, 0); // B flag
            }
        }

        i.WriteU8(tmp);

        switch (state) {
        case JOIN_SYN:
            i.WriteU8(address_id);
            i.WriteHtonU32(receiver_token);
            i.WriteHtonU32(sender_random);
            break;

        case JOIN_SYNACK:
            i.WriteU8(address_id);
            i.WriteHtonU64(truncated_hmac_64);
            i.WriteHtonU32(sender_random);
            break;

        case JOIN_ACKED:
            i.WriteU8(0); // reserved
            for (int j = 0; j < 20; ++j) {
                i.WriteU8(truncated_hmac_160[j]);
            }
            break;

        default:
            break;
        }

        return buf;
    }

    uint32_t pkg_mp_join::Deserialize(Buffer::Iterator buf) {
        uint8_t tmp = buf.ReadU8();
        subtype = static_cast<MP_SubType>(PKG_GETSUBTYPEU8(tmp));

        uint8_t option_len = this->length;

        switch (option_len) {
        case 12:
            state = JOIN_SYN;

            backup = get_bit8(tmp, 0);
            address_id = buf.ReadU8();
            receiver_token = buf.ReadNtohU32();
            sender_random = buf.ReadNtohU32();
            break;
        case 16:
            state = JOIN_SYNACK;

            backup = get_bit8(tmp, 0);
            address_id = buf.ReadU8();
            truncated_hmac_64 = buf.ReadNtohU64();
            sender_random = buf.ReadNtohU32();
            break;
        case 24:
            state = JOIN_ACKED;

            buf.ReadU8(); // reserved
            for (int j = 0; j < 20; ++j) {
                truncated_hmac_160[j] = buf.ReadU8();
            }
            break;

        default:
            state = JOIN_NONE;
            break;
        }
        return this->CalculateLength();
    }

    uint8_t pkg_mp_join::CalculateLength() {
        switch (state) {
        case JOIN_SYN:
            return 12;
        case JOIN_SYNACK:
            return 16;
        case JOIN_ACKED:
            return 24;
        default:
            return 0;
        }
    }

    TypeId pkg_mp_dss::GetTypeId() {
        static auto tid = TypeId("pkg_mp_dss")
                              .SetParent<pkg_undefine>()
                              .SetGroupName("Internet")
                              .AddConstructor<pkg_mp_dss>();
        return tid;
    }

    pkg_mp_dss::pkg_mp_dss()
        : kind(TcpOptionMptcp::Kind::MULTIPATH_TCP),
          length(0x0),
          subtype(MP_SubType::DSS),
          _is_fin(false),
          _is_wide_dsn(false),
          dsn_present(false),
          _is_wide_ack(false),
          _is_ack(false),
          _data_ack(0),
          _data_seq(0),
          _subflow_seq(0),
          data_level_length(UINT16_MAX),
          checksum(UINT16_MAX) {
    }

    pkg_mp_dss::pkg_mp_dss(pkg_header header)
        : kind(header.kind),
          length(header.length),
          subtype(header.subtype),
          _is_fin(false),
          _is_wide_dsn(false),
          dsn_present(false),
          _is_wide_ack(false),
          _is_ack(false),
          _data_ack(0),
          _data_seq(0),
          _subflow_seq(0),
          data_level_length(UINT16_MAX),
          checksum(UINT16_MAX) {
    }

    Buffer pkg_mp_dss::Serialize() {
        Buffer buf;
        this->length = CalculateLength();
        buf.AddAtEnd(this->length);
        auto i = buf.Begin();
        i.WriteU8(TcpOptionMptcp::Kind::MULTIPATH_TCP);
        i.WriteU8(length);

        uint8_t tmp = 0;
        PKG_SETSUBTYPEU8(tmp, subtype);
        i.WriteU8(tmp);

        uint8_t flags = 0;

        if (this->_is_fin) {
            set_bit8(flags, MP_DSS_FLAG_F);
        }
        if (this->_is_wide_dsn) {
            set_bit8(flags, MP_DSS_FLAG_m);
        }
        if (this->dsn_present) {
            set_bit8(flags, MP_DSS_FLAG_M);
        }
        if (this->_is_wide_ack) {
            set_bit8(flags, MP_DSS_FLAG_a);
        }
        if (this->_is_ack) {
            set_bit8(flags, MP_DSS_FLAG_A);
        }

        i.WriteU8(flags);

        // ===== Data ACK =====
        if (_is_ack) {
            if (_is_wide_ack) {
                i.WriteHtonU64(_data_ack);
            } else {
                i.WriteHtonU32(static_cast<uint32_t>(_data_ack));
            }
        }

        // ===== Mapping =====
        if (dsn_present) {
            if (_is_wide_dsn) {
                i.WriteHtonU64(_data_seq);
            } else {
                i.WriteHtonU32(static_cast<uint32_t>(_data_seq));
            }

            i.WriteHtonU32(_subflow_seq);
            i.WriteHtonU16(data_level_length);
        }
        i.WriteHtonU16(checksum);

        return buf;
    }

    uint16_t pkg_mp_dss::update_checksum() {
        uint16_t checksum = 0x0;
        auto buf = Buffer();
        auto it = buf.Begin();
        it.WriteHtonU64(this->_data_seq);
        it.WriteHtonU32(this->_subflow_seq);
        it.WriteHtonU16(this->data_level_length);
        it.WriteHtonU16(0x0U);
        it.CalculateIpChecksum(16);
        return checksum;
    }

    bool pkg_mp_dss::verify_checksum() {
        return this->checksum == this->update_checksum();
    }

    uint32_t pkg_mp_dss::Deserialize(Buffer::Iterator buf) {
        uint8_t tmp = buf.ReadU8();
        this->subtype = static_cast<MP_SubType>(PKG_GETSUBTYPEU8(tmp));

        uint8_t flags = buf.ReadU8();

        _is_fin = get_bit8(flags, MP_DSS_FLAG_F);
        _is_wide_dsn = get_bit8(flags, MP_DSS_FLAG_m);
        dsn_present = get_bit8(flags, MP_DSS_FLAG_M);
        _is_wide_ack = get_bit8(flags, MP_DSS_FLAG_a);
        _is_ack = get_bit8(flags, MP_DSS_FLAG_A);

        // ===== Data ACK =====
        if (_is_ack) {
            if (_is_wide_ack) {
                _data_ack = buf.ReadNtohU64();
            } else {
                _data_ack = buf.ReadNtohU32();
            }
        }

        // ===== Mapping =====
        if (dsn_present) {
            if (_is_wide_dsn) {
                _data_seq = buf.ReadNtohU64();
            } else {
                _data_seq = buf.ReadNtohU32();
            }

            _subflow_seq = buf.ReadNtohU32();
            data_level_length = buf.ReadNtohU16();
        }
        checksum = buf.ReadNtohU16();
        return this->CalculateLength();
    }

    uint8_t pkg_mp_dss::CalculateLength() {
        // Fixed DSS header:
        // Kind + Length + Subtype + Flags
        uint8_t size = 4;

        // ===== Data ACK section =====
        if (_is_ack) {
            // ACK present
            if (_is_wide_ack) {
                size += 8; // 64-bit ACK
            } else {
                size += 4; // 32-bit ACK
            }
        }

        // ===== Data Sequence Mapping section =====
        if (dsn_present) {
            // DSN field
            if (_is_wide_dsn) {
                size += 8; // 64-bit DSN
            } else {
                size += 4; // 32-bit DSN
            }

            size += 4; // Subflow Sequence Number (always 32-bit)
            size += 2; // Data-Level Length
        }
        size += 2; // Checksum, if require
        return size;
    }

    TypeId pkg_mp_prio::GetTypeId() {
        static auto tid = TypeId("pkg_mp_prio")
                              .SetParent<pkg_undefine>()
                              .SetGroupName("Internet")
                              .AddConstructor<pkg_mp_prio>();
        return tid;
    }

    pkg_mp_prio::pkg_mp_prio()
        : kind(TcpOptionMptcp::Kind::MULTIPATH_TCP),
          length(0x0),
          subtype(MP_SubType::MP_PRIO),
          backup(false) {
    }

    pkg_mp_prio::pkg_mp_prio(pkg_header header)
        : kind(header.kind),
          length(header.length),
          subtype(header.subtype),
          backup(false) {
    }

    Buffer pkg_mp_prio::Serialize() {
        Buffer buffer;
        this->length = CalculateLength();
        buffer.AddAtEnd(this->length);
        auto it = buffer.Begin();

        it.WriteU8(TcpOptionMptcp::Kind::MULTIPATH_TCP);
        it.WriteU8(this->CalculateLength());
        uint8_t tmp = 0;
        PKG_SETSUBTYPEU8(tmp, MP_SubType::MP_PRIO);
        set_bit8(tmp, MP_PRIO_FLAG_B);
        it.WriteU8(tmp);
        return buffer;
    }

    uint32_t pkg_mp_prio::Deserialize(Buffer::Iterator it) {
        // this->kind = it.ReadU8();
        // this->length = it.ReadU8();
        uint8_t tmp = it.ReadU8();
        // subtype = PKG_GETSUBTYPEU8(tmp);
        this->backup = get_bit8(tmp, MP_PRIO_FLAG_B);
        return this->CalculateLength();
    }

    uint8_t pkg_mp_prio::CalculateLength() {
        return 3;
    }

    TypeId pkg_mp_add_addr::GetTypeId() {
        static auto tid = TypeId("pkg_mp_add_addr")
                              .SetParent<pkg_undefine>()
                              .SetGroupName("Internet")
                              .AddConstructor<pkg_mp_add_addr>();
        return tid;
    }

    pkg_mp_add_addr::pkg_mp_add_addr()
        : kind(TcpOptionMptcp::Kind::MULTIPATH_TCP),
          length(0x0),
          subtype(ADD_ADDR),
          echo(false),
          address_id(0x0),
          _is_ipv6(false),
          ipv4Addr(Ipv4Address::GetZero()),
          ipv6Addr(Ipv6Address::GetZero()),
          has_port(false),
          port(0),
          truncated_hmac(0) {
    }

    pkg_mp_add_addr::pkg_mp_add_addr(pkg_header header)
        : kind(header.kind),
          length(header.length),
          subtype(header.subtype),
          echo(false),
          address_id(0),
          _is_ipv6(false),
          ipv4Addr(Ipv4Address::GetZero()),
          ipv6Addr(Ipv6Address::GetZero()),
          has_port(false),
          port(0),
          truncated_hmac(0) {
    }

    // #include <ns3/
    Buffer pkg_mp_add_addr::Serialize() {
        Buffer buf;
        this->length = CalculateLength();
        buf.AddAtEnd(this->length);
        auto i = buf.Begin();
        i.WriteU8(TcpOptionMptcp::Kind::MULTIPATH_TCP);
        i.WriteU8(this->length);

        uint8_t tmp = 0U;
        PKG_SETSUBTYPEU8(tmp, ADD_ADDR);
        if (this->echo) {
            set_bit8(tmp, MP_ADD_ADDR_FLAG_E);
        }

        i.WriteU8(tmp);
        i.WriteU8(address_id);

        // ===== Address =====
        if (this->_is_ipv6) {
            uint8_t buf6[16];
            this->ipv6Addr.Serialize(buf6);
            for (int _i = 0; _i < 16; _i++) {
                i.WriteU8(buf6[_i]);
            }
        } else {
            // write IPv4 address in network byte order
            i.WriteHtonU32(this->ipv4Addr.Get());
        }

        // ===== Port =====
        if (has_port) {
            i.WriteHtonU16(port);
        }

        // ===== HMAC =====
        if (!echo) {
            this->mk_hmac();
            i.WriteHtonU64(truncated_hmac);
        }

        return buf;
    }

    uint32_t pkg_mp_add_addr::Deserialize(Buffer::Iterator buf) {
        uint8_t tmp = buf.ReadU8();
        subtype = static_cast<MP_SubType>(PKG_GETSUBTYPEU8(tmp));

        echo = get_bit8(tmp, MP_ADD_ADDR_FLAG_E);
        if (echo) {
            NS_LOG_DEBUG("pkg_add_addr: recieved echo");
        }
        address_id = buf.ReadU8();

        size_t remain = this->length - 4;

        // Determine IPv4 or IPv6
        // ===== Address =====
        if ((remain == (16U + (!this->echo) * 8U)) || (remain == (16U + 2U + (!this->echo) * 8U))) {
            // IPv6
            this->_is_ipv6 = true;
            uint8_t buf6[16];
            for (size_t i = 0; i < 16; i++) {
                buf6[i] = buf.ReadU8();
            }
            this->ipv6Addr = Ipv6Address::Deserialize(buf6);
            remain -= 16;
        } else {
            // IPv4
            this->_is_ipv6 = false;
            uint32_t addr4 = buf.ReadNtohU32();
            this->ipv4Addr = Ipv4Address(addr4);
            remain -= 4;
        }
        // ===== Port =====
        if (remain == (2U + (!this->echo) * 8U)) {
            has_port = true;
            port = buf.ReadNtohU16();
            remain -= 2;
        } else {
            has_port = false;
        }

        // ===== HMAC =====
        if (!echo && remain == 8) {
            truncated_hmac = buf.ReadNtohU64();
        }
        NS_LOG_DEBUG("pkg_mp_add_addr::Deserialize()");
        return this->CalculateLength();
    }

    void pkg_mp_add_addr::mk_hmac() {
        this->truncated_hmac = 0x0;
    }

    uint8_t pkg_mp_add_addr::CalculateLength() {
        size_t size = 4; // Kind + Length + Subtype + Flag/ID
        size += (_is_ipv6 ? 16 : 4);
        if (has_port) {
            size += 2;
        }
        if (!echo) {
            size += 8;
        }
        return size;
    }

    TypeId pkg_mp_fail::GetTypeId() {
        static auto tid = TypeId("pkg_mp_fail")
                              .SetParent<pkg_undefine>()
                              .SetGroupName("Internet")
                              .AddConstructor<pkg_mp_fail>();
        return tid;
    }

    pkg_mp_fail::pkg_mp_fail()
        : kind(TcpOptionMptcp::Kind::MULTIPATH_TCP),
          length(0x0),
          subtype(MP_FAIL),
          drop_dsn(0x0) {
    }

    pkg_mp_fail::pkg_mp_fail(pkg_header header)
        : kind(header.kind),
          length(header.length),
          subtype(header.subtype) {
    }

    Buffer pkg_mp_fail::Serialize() {
        Buffer buf;
        this->length = CalculateLength();
        buf.AddAtEnd(this->length);
        auto out = buf.Begin();
        out.WriteU8(TcpOptionMptcp::Kind::MULTIPATH_TCP);
        out.WriteU8(CalculateLength());
        uint8_t tmp{};
        PKG_SETSUBTYPEU8(tmp, MP_FAIL);
        out.WriteU8(tmp);
        out.WriteU8(0);
        out.WriteHtonU64(this->drop_dsn);
        return buf;
    }

    uint32_t pkg_mp_fail::Deserialize(Buffer::Iterator in) {
        in.ReadU16();
        this->drop_dsn = in.ReadNtohU64();
        return this->CalculateLength();
    }

    uint8_t pkg_mp_fail::CalculateLength() {
        return 12;
    }

    TypeId pkg_mp_remove_addr::GetTypeId() {
        static auto tid = TypeId("pkg_mp_remove_addr")
                              .SetParent<pkg_undefine>()
                              .SetGroupName("Internet")
                              .AddConstructor<pkg_mp_remove_addr>();
        return tid;
    }

    pkg_mp_remove_addr::pkg_mp_remove_addr()
        : kind(TcpOptionMptcp::Kind::MULTIPATH_TCP),
          length(0),
          subtype(MP_SubType::REMOVE_ADDR) {
    }

    pkg_mp_remove_addr::pkg_mp_remove_addr(pkg_header header)
        : kind(header.kind),
          length(header.length),
          subtype(header.subtype) {
    }

    void pkg_mp_remove_addr::AddAddressId(uint8_t id) {
        addresses_id.push_back(id & 0x0F); // Address ID 僅 4 bits
    }

    uint8_t pkg_mp_remove_addr::GetAddressCount() const {
        return static_cast<uint8_t>(addresses_id.size());
    }

    std::vector<uint8_t> pkg_mp_remove_addr::GetAddressIDList() const {
        return this->addresses_id;
    }

    Buffer pkg_mp_remove_addr::Serialize() {
        Buffer buf;
        this->length = CalculateLength();
        buf.AddAtEnd(this->length);
        auto i = buf.Begin();

        i.WriteU8(TcpOptionMptcp::Kind::MULTIPATH_TCP);
        i.WriteU8(CalculateLength());

        uint8_t tmp{};
        PKG_SETSUBTYPEU8(tmp, MP_SubType::REMOVE_ADDR);
        i.WriteU8(tmp);

        if (addresses_id.empty()) {
            return Buffer(); // 不合法，但避免 crash
        }

        // 第一個 byte: reserved(4 bits) + first address id
        tmp = 0U;
        tmp |= (addresses_id[0] & 0x0F);
        i.WriteU8(tmp);

        // 其餘 address id
        for (size_t idx = 1; idx < addresses_id.size(); ++idx) {
            i.WriteU8(addresses_id[idx] & 0x0F);
        }

        return buf;
    }

    uint32_t pkg_mp_remove_addr::Deserialize(Buffer::Iterator buf) {
        addresses_id.clear();
        uint8_t tmp = buf.ReadU8();
        this->subtype = static_cast<MP_SubType>(PKG_GETSUBTYPEU8(tmp));
        uint8_t first = buf.ReadU8();
        // 低 4 bits 為 Address ID
        addresses_id.push_back(first & 0x0F);
        uint8_t remain = this->length - 4; // 扣除 header 4 bytes

        for (uint8_t i = 0; i < remain; ++i) {
            uint8_t id = buf.ReadU8();
            addresses_id.push_back(id & 0x0F);
        }
        return this->CalculateLength();
    }

    uint8_t pkg_mp_remove_addr::CalculateLength() {
        uint8_t n = static_cast<uint8_t>(addresses_id.size());
        if (n == 0) {
            return 4; // 最小保護值
        }
        return static_cast<uint8_t>(3 + n);
    }

    pkg_mp_fastclose::pkg_mp_fastclose()
        : kind(TcpOptionMptcp::Kind::MULTIPATH_TCP),
          length(0x0),
          subtype(MP_SubType::MP_FASTCLOSE),
          receiver_key(0) {
    }

    pkg_mp_fastclose::pkg_mp_fastclose(pkg_header header)
        : kind(header.kind),
          length(header.length),
          subtype(header.subtype),
          receiver_key(0x0) {
    }

    uint64_t pkg_mp_fail::get_fail_dsn() {
        return this->drop_dsn;
    }

    void pkg_mp_fail::set_fail_dsn(uint64_t dsn) {
        this->drop_dsn = dsn;
    }

    TypeId pkg_mp_fastclose::GetTypeId() {
        static auto tid = TypeId("pkg_mp_fastclose")
                              .SetParent<pkg_undefine>()
                              .SetGroupName("Internet")
                              .AddConstructor<pkg_mp_fastclose>();
        return tid;
    }

    Buffer pkg_mp_fastclose::Serialize() {
        Buffer buf;
        this->length = CalculateLength();
        buf.AddAtEnd(this->length);
        auto i = buf.Begin();

        i.WriteU8(TcpOptionMptcp::Kind::MULTIPATH_TCP);
        i.WriteU8(CalculateLength());

        uint8_t tmp{};
        PKG_SETSUBTYPEU8(tmp, MP_FASTCLOSE);
        i.WriteU8(tmp);

        // reserved byte
        i.WriteU8(0U);

        // receiver key (64 bits)
        if (receiver_key) {
            i.WriteHtonU64(receiver_key);
        }

        return buf;
    }

    uint32_t pkg_mp_fastclose::Deserialize(Buffer::Iterator buf) {
        uint8_t tmp = buf.ReadU8();
        this->subtype = PKG_GETSUBTYPEU8(tmp);

        // skip reserved
        buf.ReadU8();

        receiver_key = buf.ReadNtohU64();
        return this->CalculateLength();
    }

    uint8_t pkg_mp_fastclose::CalculateLength() {
        return 12;
    }

    TypeId pkg_mp_tcprst::GetTypeId() {
        static auto tid = TypeId("pkg_mp_tcprst")
                              .SetParent<pkg_undefine>()
                              .SetGroupName("Internet")
                              .AddConstructor<pkg_mp_tcprst>();
        return tid;
    }

    pkg_mp_tcprst::pkg_mp_tcprst()
        : flag_U(false),
          flag_V(false),
          flag_W(false),
          transient_error(false),
          kind(TcpOptionMptcp::Kind::MULTIPATH_TCP),
          length(0),
          subtype(MP_SubType::MP_TCPRST),
          reason(Reason::UNSPECIFIED_ERROR) {
    }

    pkg_mp_tcprst::pkg_mp_tcprst(pkg_header header)
        : flag_U(false),
          flag_V(false),
          flag_W(false),
          transient_error(false),
          kind(header.kind),
          length(header.length),
          subtype(header.subtype),
          reason(Reason::UNSPECIFIED_ERROR) {
    }

    Buffer pkg_mp_tcprst::Serialize() {
        Buffer buf;
        this->length = CalculateLength();
        buf.AddAtEnd(this->length);
        auto i = buf.Begin();

        i.WriteU8(TcpOptionMptcp::Kind::MULTIPATH_TCP);
        i.WriteU8(CalculateLength());

        uint8_t tmp{0U};
        PKG_SETSUBTYPEU8(tmp, MP_TCPRST);

        if (transient_error) {
            set_bit8(tmp, MP_TCPRST_FLAG_T);
        }
        i.WriteU8(tmp);
        i.WriteU8(this->reason);

        return buf;
    }

    uint32_t pkg_mp_tcprst::Deserialize(Buffer::Iterator buf) {
        // this->subtype = static_cast<MP_SubType>(PKG_GETSUBTYPEU8(tmp));
        uint8_t flag_reason = buf.ReadU8();
        flag_reason = buf.ReadU8();
        this->transient_error = get_bit8(flag_reason, MP_TCPRST_FLAG_T);
        this->reason = static_cast<Reason>(flag_reason & 0x0F);
        return this->CalculateLength();
    }

    uint8_t pkg_mp_tcprst::CalculateLength() {
        return 4;
    }
} // namespace ns3
