/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright 2014 University of Sussex, UK.
 * Copyright 2007 University of Washington
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author:  Tom Henderson (tomhend@u.washington.edu)
 * Modified by Morteza Kheirkhah (m.kheirkhah@sussex.ac.uk)
 */

#include "mp-tcp-file-sink.h"

#include "ns3/address-utils.h"
#include "ns3/address.h"
#include "ns3/inet-socket-address.h"
#include "ns3/ipv4.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/socket.h"
#include "ns3/string.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/udp-socket.h"

#include <array>
#include <filesystem>
#include <openssl/evp.h>
#include <set>
// #include "ns3/mp-tcp-typedefs.h"

using namespace std;

NS_LOG_COMPONENT_DEFINE("MpTcpFileSink");

namespace ns3 {

    NS_OBJECT_ENSURE_REGISTERED(MpTcpFileSink);

    inline vector<MpTcpAddressInfo> get_address(Ptr<Node> node, Address listen_addr) {
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        // auto isock = node->GetObject<InetSocketAddress>();
        auto listen_addr_isocket = InetSocketAddress::ConvertFrom(listen_addr);
        std::vector<std::vector<Ipv4InterfaceAddress>> ifs;
        size_t addr_num = 0;
        std::vector<MpTcpAddressInfo> rtn;
        std::stringstream ss;
        bool is_any = (listen_addr_isocket.GetIpv4() == Ipv4Address::GetZero());
        for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++) {
            for (uint32_t j = 0; j < ipv4->GetNAddresses(i); j++) {
                Ipv4InterfaceAddress addr = ipv4->GetAddress(i, j);
                if (addr.GetAddress().IsLocalhost()) {
                    continue;
                }
                uint16_t port = 0;
                if (is_any || (addr.GetAddress() == listen_addr_isocket.GetIpv4())) {
                    port = listen_addr_isocket.GetPort();
                }
                MpTcpAddressInfo addrInfo{addr.GetAddress(), port};
                addrInfo.mask = addr.GetMask();
                rtn.push_back(addrInfo);
                addr_num++;
                ss << "\tInterface " << i << " IP " << addrInfo.ipv4Addr << ":" << +addrInfo.port
                   << std::endl;
            }
        }
        NS_LOG_INFO("get ips from node:\n" << ss.str());
        return rtn;
    }

    TypeId MpTcpFileSink::GetTypeId(void) {
        static TypeId tid =
            TypeId("ns3::MpTcpFileSink")
                .SetParent<Application>()
                .AddConstructor<MpTcpFileSink>()
                .AddAttribute("Local",
                              "The Address on which to Bind the rx socket.",
                              AddressValue(),
                              MakeAddressAccessor(&MpTcpFileSink::m_local),
                              MakeAddressChecker())
                .AddAttribute("Protocol",
                              "The type id of the protocol to use for the rx socket.",
                              TypeIdValue(TcpSocketFactory::GetTypeId()),
                              MakeTypeIdAccessor(&MpTcpFileSink::m_tid),
                              MakeTypeIdChecker())
                .AddAttribute("ExportBaseDir",
                              "Base Diretory of export file.",
                              StringValue("output"),
                              MakeStringAccessor(&MpTcpFileSink::m_exportBaseDirStr),
                              MakeStringChecker())
                .AddAttribute("Timeout",
                              "Timeout for receiving files",
                              UintegerValue(60),
                              MakeUintegerAccessor(&MpTcpFileSink::m_timeout),
                              MakeUintegerChecker<uint32_t>());
        //    .AddTraceSource ("Rx", "A packet has been received",
        //                     MakeTraceSourceAccessor (&MpTcpPacketSink::m_rxTrace));
        return tid;
    }

    MpTcpFileSink::MpTcpFileSink() {
        NS_LOG_FUNCTION(this);
        m_socket = 0;
        m_totalRx = 0;
        m_fdtReceived = false;
    }

    MpTcpFileSink::~MpTcpFileSink() {
        NS_LOG_FUNCTION(this);
    }

    uint32_t MpTcpFileSink::GetTotalRx() const {
        return m_totalRx;
    }

    void MpTcpFileSink::DoDispose(void) {
        NS_LOG_FUNCTION(this);
        m_socket = 0;
        // chain up
        Application::DoDispose();
    }

    // Application Methods
    void MpTcpFileSink::StartApplication() // Called at time specified by Start
    {
        NS_LOG_FUNCTION(this);
        // Create the socket if not already
        if (!m_socket) {
            size = 2000;
            // buf = new uint8_t[size];
            // m_socket = CreateObject<MpTcpSocketBase>(GetNode());
            m_socket = DynamicCast<MpTcpSocketBase>(Socket::CreateSocket(GetNode(), m_tid));
            m_socket->Bind(m_local);
            m_socket->Listen();
            NS_LOG_LOGIC("StartApplication -> MptcpPacketSink got an listening socket "
                         << m_socket << " binded to addrs:port  "
                         << InetSocketAddress::ConvertFrom(m_local).GetIpv4() << ":"
                         << InetSocketAddress::ConvertFrom(m_local).GetPort());
        }
        NS_ASSERT(this->m_exportBaseDirStr != "");
        std::filesystem::path export_dir = this->m_exportBaseDirStr;
        std::filesystem::path tmp_dir = export_dir / ".tmp";
        std::error_code ec;
        if (std::filesystem::exists(export_dir, ec)) {
            std::filesystem::remove_all(export_dir, ec);
        }
        std::filesystem::create_directories(tmp_dir, ec);
        if (ec) {
            NS_FATAL_ERROR("ReceiveFile() -> cannot create tmp dir: " << ec.message());
        }
        m_socket->SetLocalAddress(get_address(m_node, m_local));
        m_socket->SetRecvCallback(MakeCallback(&MpTcpFileSink::HandleRead, this));
        m_socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                    MakeCallback(&MpTcpFileSink::HandleAccept, this));
        m_socket->SetCloseCallbacks(MakeCallback(&MpTcpFileSink::HandlePeerClose, this),
                                    MakeCallback(&MpTcpFileSink::HandlePeerError, this));
        // this->m_export = ofstream("rx_buf.txt");
    }

    void MpTcpFileSink::StopApplication() // Called at time specified by Stop
    {
        NS_LOG_FUNCTION(this); //
        NS_LOG_WARN(Simulator::Now().GetSeconds()
                    << " MpTcpPacketSink -> Total received bytes " << m_totalRx);
        while (!m_socketList.empty()) // these are accepted sockets, close them
        {
            Ptr<Socket> acceptedSocket = m_socketList.front();
            m_socketList.pop_front();
            NS_LOG_INFO("MpTcpPacketSink -> Drop this accepted socket ,"
                        << acceptedSocket << ", and call Close on it ");
            acceptedSocket->Close();
            NS_LOG_INFO("MpTcpPacketSink -> Now SocketListSize is " << m_socketList.size());
        }
        if (m_socket) {
            NS_LOG_INFO("MpTcpPacketSink -> FINALY closing the listening socket, " << m_socket);
            m_socket->Close();
            m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
        }
    }

    bool DecodeHeader(Buffer::Iterator& out, FileDescriptor& out_fdt) {
        std::string line;
        out_fdt.chunck_id = 0;
        out_fdt.chunck_num = 1;
        stringstream ss;
        // size_t byte_read{0};
        while (!out.IsEnd()) {
            while (out.PeekU8() != '\n') {
                ss << out.ReadU8();
            }
            out.Next();
            line = ss.str();
            ss.str("");
            // 處理 Windows 換行符號可能帶有的 \r
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (line.empty()) {
                return true;
            }
            size_t colon_pos = line.find(':');
            if (colon_pos == std::string::npos) {
                continue;
            }
            std::string key = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);

            // 根據 Key 填入對應的 fdt 欄位
            if (key == "chunk_id") {
                out_fdt.chunck_id = std::stoul(value);
            } else if (key == "chunk_num") {
                out_fdt.chunck_num = std::stoul(value);
            } else if (key == "filename") {
                out_fdt.filename = value;
            } else if (key == "checksum") {
                out_fdt.checksum = value;
            } else if (key == "bytes") {
                out_fdt.byte = std::stoull(value);
            } else if (key == "stat") {
                out_fdt.stat = (value == "file" ? fdt_stat::file : fdt_stat::close);
            }
        }
        return false;
    }

    void MpTcpFileSink::HandleRead(Ptr<Socket> socket) {
        NS_LOG_FUNCTION(this << m_socket);
        Ptr<MpTcpSocketBase> mpSocket = DynamicCast<MpTcpSocketBase>(socket);
        // uint32_t dataAmount = mpSocket->Recv(size);
        Buffer buf = mpSocket->AcceptRecvBuf(UINT32_MAX);
        const uint32_t dataAmount = buf.GetSize();
        // uint32_t dataAmount = m_socket->Recv(buf, size);
        uint8_t tmp[512];
        auto toRead = dataAmount;
        size_t readSize;
        auto it = buf.Begin();
        while ((readSize = std::min(sizeof(tmp), static_cast<size_t>(toRead)))) {
            it.Read(tmp, readSize);
            m_export.write((char*)tmp, readSize);
            toRead -= readSize;
        }
        auto in = buf.Begin();
        while (in.GetRemainingSize()) {
            if (!this->m_fdtReceived) {
                this->m_fdtReceived = DecodeHeader(in, this->m_destFdt);
                if (this->m_fdtReceived) {
                    NS_LOG_INFO("FDT: " << this->m_destFdt.filename
                                        << ", chunk_id: " << +this->m_destFdt.chunck_id
                                        << ", chunk_num: " << +this->m_destFdt.chunck_num
                                        << ", bytes: " << this->m_destFdt.byte);
                } else {
                    return;
                }
                if (this->m_destFdt.stat == fdt_stat::close) {
                    NS_LOG_INFO("FDT: close @" << Simulator::Now().GetSeconds() << "s");
                    m_socket->Close(); //?
                    Simulator::Stop(Seconds(2));
                    return;
                }
            }
            ReceiveFile(in);
        }
        m_totalRx += dataAmount;
        NS_LOG_DEBUG("MpTcpPacketSink:HandleRead() -> Received " << dataAmount << " bytes total Rx "
                                                                 << m_totalRx);
    }

    inline string GetCheckSum(std::ifstream& fd, std::streamoff off, uint128_t len) {
        NS_ASSERT_MSG(fd.is_open(), "cannot open file");

        fd.clear();
        fd.seekg(off, std::ios::beg);

        // 1. 使用 std::unique_ptr 與自訂 deleter 實現 RAII，確保 ctx 會自動釋放
        using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
        EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

        NS_ASSERT_MSG(ctx, "cannot create EVP!");

        if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
            return {};
        }

        char buf[4096];
        uint128_t remaining = len;

        while (remaining > 0 && fd) {
            std::streamsize to_read = static_cast<std::streamsize>(
                std::min(static_cast<uint128_t>(sizeof(buf)), remaining));

            fd.read(buf, to_read);
            std::streamsize n = fd.gcount();

            if (n > 0) {
                if (EVP_DigestUpdate(ctx.get(), buf, n) != 1) {
                    return {};
                }
                remaining -= n;
            } else {
                break;
            }
        }

        uint8_t hash[SHA256_DIGEST_LENGTH];
        unsigned int length = 0;

        if (EVP_DigestFinal_ex(ctx.get(), hash, &length) != 1) {
            return {};
        }
        unsigned int b64_len = 4 * ((length + 2) / 3);
        std::vector<uint8_t> b64_out(b64_len + 1);

        int encoded_len = EVP_EncodeBlock(b64_out.data(), hash, length);
        if (encoded_len >= 0) {
            b64_out[encoded_len] = '\0';
        }

        std::stringstream ss;
        ss << "sha-256=" << b64_out.data();
        return ss.str();
    }

    bool MpTcpFileSink::ReceiveFile(Buffer::Iterator& out) {
        NS_LOG_FUNCTION(this << out.GetRemainingSize() << "FDT(" << this->m_destFdt.filename
                             << ", chunk_id: " << +this->m_destFdt.chunck_id << ", chunk_num: "
                             << +this->m_destFdt.chunck_num << ", bytes: " << this->m_destFdt.byte
                             << ", acknowledged: " << this->m_destFdt.acknowledged << ")");
        if (out.GetRemainingSize() == 0) {
            NS_ABORT_MSG("ReceiveFile() -> empty payload for file " << m_destFdt.filename);
            return false;
        }
        FileDescriptor& fdt = this->m_destFdt;
        std::filesystem::path export_dir = this->m_exportBaseDirStr;
        std::filesystem::path tmp_dir = export_dir / ".tmp";
        std::filesystem::path export_path;

        bool is_chunck = (fdt.chunck_num > 1);
        if (is_chunck) {
            export_path = export_dir / (".tmp" + fdt.filename + "." + to_string(fdt.chunck_id));
        } else {
            export_path = export_dir / fdt.filename;
        }

        std::ofstream ofs(export_path, ios::app | ios::binary);
        NS_ABORT_MSG_IF(!ofs.is_open(),
                        "ReceiveFile() -> cannot open file for writing: " << export_path);
        size_t actual_read =
            std::min(static_cast<size_t>(out.GetRemainingSize()), fdt.byte - fdt.acknowledged);
        size_t toRead = actual_read;
        uint8_t _buf[1024];
        while (toRead > 0) {
            size_t _read = std::min(static_cast<size_t>(toRead), sizeof(_buf));
            out.Read(_buf, _read);
            ofs.write((char*)_buf, _read);
            toRead -= _read;
            fdt.acknowledged += _read;
        }
        ofs.close();
        if (fdt.acknowledged >= fdt.byte) {
            std::ifstream ifs(export_path, ios::binary);
            this->m_fdtReceived = false;
            const std::string actual_checksum = GetCheckSum(ifs, 0, fdt.acknowledged);
            if (actual_checksum != fdt.checksum) {
                NS_LOG_ERROR("ReceiveFile() -> checksum mismatch for file"
                             << fdt.filename << ": expected " << fdt.checksum << ", got "
                             << actual_checksum);
                std::filesystem::remove(export_path);
                return false;
            }
            NS_LOG_UNCOND("MpTcpFileSink::ReceiveFile -> received file: "
                          << fdt.filename << "@" << Simulator::Now().GetSeconds() << "s");
            return true;
        }
        return false;
    }

    void MpTcpFileSink::MergeChunck(std::string filename, uint8_t chunck_num) {
        namespace fs = std::filesystem;

        // 建立路徑物件
        fs::path baseDir(this->m_exportBaseDirStr);
        fs::path tmpDir = baseDir / ".tmp";

        // 檢查 .tmp 目錄是否存在
        NS_ASSERT_MSG(!fs::exists(tmpDir) || !fs::is_directory(tmpDir),
                      "Temp directory does not exist: " << tmpDir);

        fs::path outputFilepath = baseDir / filename;
        std::ofstream outFile(outputFilepath, std::ios::binary);
        if (!outFile.is_open()) {
            NS_LOG_ERROR("Failed to create output file: " << outputFilepath);
            return;
        }

        bool mergeSuccess = true;
        for (uint8_t i = 0; i < chunck_num; ++i) {
            // 組合出 chunk 檔名：<filename>.<chunk_id>
            fs::path chunkPath = tmpDir / (filename + "." + std::to_string(i));

            if (!fs::exists(chunkPath)) {
                NS_LOG_INFO("Chunk file missing: " << chunkPath);
                mergeSuccess = false;
                break;
            }
            std::ifstream inFile(chunkPath, std::ios::binary);
            if (!inFile.is_open()) {
                NS_FATAL_ERROR("Failed to open chunk file: " << chunkPath);
                mergeSuccess = false;
                break;
            }
            outFile << inFile.rdbuf();
        }
        outFile.close();

        if (mergeSuccess) {
            NS_LOG_INFO("Successfully merged: " << filename);
            for (uint8_t i = 0; i < chunck_num; ++i) {
                fs::path chunkPath = tmpDir / (filename + "." + std::to_string(i));
                std::error_code ec;
                fs::remove(chunkPath, ec); // 刪除檔案，忽略錯誤
            }
        } else {
            NS_LOG_WARN("Failed to merge: " << filename);
        }
    }

    void MpTcpFileSink::HandlePeerClose(Ptr<Socket> socket) {
        NS_LOG_FUNCTION(this << socket);
        //  list<Ptr<Socket> >::iterator it = std::find(m_socketList.begin(), m_socketList.end(),
        //  socket); if (it != m_socketList.end())
        //    {
        //      m_socketList.erase(it);
        //      NS_LOG_UNCOND("A Socket has been Removed with Normal callback");
        //    }
    }

    void MpTcpFileSink::HandlePeerError(Ptr<Socket> socket) {
        //  list<Ptr<Socket> >::iterator it = std::find(m_socketList.begin(), m_socketList.end(),
        //  socket); if (it != m_socketList.end())
        //    {
        //      m_socketList.erase(it);
        //      NS_LOG_UNCOND("A Socket has been Removed with Error callback");
        //    }
        NS_LOG_FUNCTION(this << socket);
    }

    void MpTcpFileSink::HandleAccept(Ptr<Socket> s, const Address& from) {
        NS_LOG_FUNCTION(this << s << from);
        s->SetRecvCallback(MakeCallback(&MpTcpFileSink::HandleRead, this));
        //  s->SetCloseCallbacks(MakeCallback(&MpTcpPacketSink::HandlePeerClose, this),
        //      MakeCallback(&MpTcpPacketSink::HandlePeerError, this));
        m_socketList.push_back(s);

        NS_LOG_INFO("MptcpPacketSink got an new connection. SocketList: " << m_socketList.size());
    }

    Ptr<MpTcpSocketBase> MpTcpFileSink::getMpTcpSocket() {
        return m_socket;
    }

} // namespace ns3
