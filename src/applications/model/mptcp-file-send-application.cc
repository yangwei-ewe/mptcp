/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014 University of Sussex (UK)
 * Copyright (c) 2010 Georgia Institute of Technology
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
 * Author: George F. Riley <riley@ece.gatech.edu>
 * Modified by Morteza Kheikhah <m.kheirkhah@sussex.ac.uk>
 */

#include "mptcp-file-send-application.h"

#include "ns3/address.h"
#include "ns3/hash.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/socket.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/uinteger.h"

#include <filesystem>
#include <map>
#include <openssl/evp.h>
#include <sstream>

NS_LOG_COMPONENT_DEFINE("MpTcpFileSendApplication");

namespace ns3 {

    NS_OBJECT_ENSURE_REGISTERED(MpTcpFileSendApplication);

    inline string GetCheckSum(std::ifstream& fd, std::streamoff off, uint128_t len) {
        NS_ABORT_MSG_IF(!fd.is_open(), "cannot open file");

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

    std::string GenHeader(const FileDescriptor fdt) {
        if (fdt.stat == fdt_stat::close) {
            return "stat:close\n\n";
        }
        std::map<std::string, std::string> keys = {{"stat", "file"},
                                                   {"filename", fdt.filename},
                                                   {"checksum", fdt.checksum},
                                                   {"bytes", std::to_string(fdt.byte)}};
        ostringstream oss;
        if (fdt.chunck_num > 1) {
            oss << "chunk_id:" << std::to_string(fdt.chunck_id) << "\n"
                << "chunk_num:" << std::to_string(fdt.chunck_num) << "\n";
        }
        for (auto it : keys) {
            oss << it.first << ":" << it.second << '\n';
        }
        oss << '\n'; // new line to end header
        return oss.str();
    }

    Controler::Controler(FileDescriptor _fdt)
        : _fdt(_fdt),
          offset(0) {};

    HeaderControler::HeaderControler(FileDescriptor _fdt)
        : Controler(_fdt) {
        this->header = GenHeader(_fdt);
        NS_LOG_DEBUG("heade size: " << this->header.size());
    }

    Buffer HeaderControler::Read(size_t len) {
        NS_LOG_FUNCTION(this << offset);
        if (this->isEnd()) {
            return {};
        }
        size_t actual_read = std::min(len, this->header.size() - this->offset);
        Buffer buf;
        buf.AddAtEnd(actual_read);
        auto in = buf.Begin();
        in.Write((uint8_t*)(this->header.c_str() + this->offset), actual_read);
        this->offset += actual_read;
        return buf;
    }

    bool HeaderControler::isEnd() const {
        return (this->offset >= this->header.size() - 1); //?
    }

    FileControler::FileControler(FileDescriptor _fdt)
        : Controler(_fdt),
          fd() {
        if (this->fd.is_open()) {
            this->fd.close();
        }
        this->fd.clear();
        this->fd.open(this->_fdt.filename);
        if (!this->fd.is_open()) {
            NS_ASSERT_MSG(this->fd.is_open(), "cannot open file: " << _fdt.filename);
        }
        this->fd.seekg(0, ios::end);
        this->fileEnd = this->fd.tellg();
        this->fd.close();
    }

    Buffer FileControler::Read(size_t len) {
        if (this->isEnd()) {
            return {};
        }
        if (!this->fd.is_open()) {
            this->fd.open(this->_fdt.filename);
            NS_ASSERT(this->fd.is_open());
            this->fd.seekg(this->_fdt.start_from, ios::beg);
        }
        Buffer buf;
        size_t actual_read =
            std::min(len,
                     static_cast<size_t>(this->fileEnd - streampos(this->_fdt.start_from) -
                                         streamoff(offset)));
        buf.AddAtEnd(actual_read);
        auto in = buf.Begin();
        size_t to_read{actual_read};
        uint8_t _buf[512];
        while (to_read > 0) {
            size_t read = std::min(to_read, sizeof(_buf));
            this->fd.read((char*)_buf, read);
            in.Write(_buf, read);
            to_read -= read;
        }
        this->offset += actual_read;
        return buf;
    }

    bool FileControler::isEnd() const {
        return (streamoff(this->offset) + streamoff(this->_fdt.start_from) >= this->fileEnd);
    }

    BufferController::BufferController(const ns3::StringVector& fileList) {
        // this->pkgs = pkgs;
        for (auto file : fileList) {
            auto fd = ifstream(file, ios::binary);
            NS_ASSERT_MSG(fd.is_open(), "cannot open file: " << file);
            fd.seekg(0, std::ios::end);
            size_t fileSize = fd.tellg();
            fd.seekg(0, std::ifstream::beg);
            uint8_t chunck_num = static_cast<uint8_t>(
                std::ceil(static_cast<size_t>(fileSize - std::streampos(0)) * 1.0 / UINT64_MAX));
            for (uint8_t i{0}; i < chunck_num; i++) {
                size_t byte_left = std::min(fileSize - (i * UINT64_MAX), UINT64_MAX);
                auto _fdt = FileDescriptor{fdt_stat::file,
                                           file,
                                           GetCheckSum(fd, i * UINT64_MAX, byte_left),
                                           i,
                                           chunck_num,
                                           i * UINT64_MAX,
                                           byte_left};
                NS_LOG_INFO("FDT: " << _fdt.filename << ", chunk_id: " << +_fdt.chunck_id
                                    << ", chunk_num: " << +_fdt.chunck_num
                                    << ", bytes: " << _fdt.byte);
                this->sendQueue.push_back(std::make_shared<HeaderControler>(_fdt));
                this->sendQueue.push_back(std::make_shared<FileControler>(_fdt));
            }
            // auto checksum = GetCheckSum(fd);
        }
        this->sendQueue.push_back(
            std::make_shared<HeaderControler>(FileDescriptor{.stat = fdt_stat::close}));
        NS_LOG_DEBUG("BufferController::BufferController -> " << +this->sendQueue.size()
                                                              << " to send.");
    }

    Buffer BufferController::Read(size_t len) {
        NS_LOG_FUNCTION(this << len);
        // size_t to_read = len, tot_read{0};
        // Buffer rtn;
        // rtn.AddAtEnd(len);
        // auto in = rtn.Begin();
        // while (this->pkgs.size() && to_read > 0) {
        //     size_t read{};
        //     Buffer buf;
        //     if (is_file) {
        //         buf = ReadFile(to_read, read);
        //     } else {
        //         buf = ReadHeader(to_read, read);
        //     }
        //     tot_read += read;
        //     to_read -= read;
        //     in.Write(buf.Begin(), buf.End());
        // }
        // return rtn;
        auto rtn = (*this->sendQueue.begin())->Read(len);
        NS_LOG_DEBUG("BufferController::Read -> readsize: " << rtn.GetSize());
        if ((*this->sendQueue.begin())->isEnd()) {
            this->sendQueue.erase(this->sendQueue.begin());
            NS_LOG_DEBUG("BufferController::Read -> deleted. left: " << this->sendQueue.size());
        }
        return rtn;
    }

    bool BufferController::isEnd() const {
        return !this->sendQueue.size();
    }

    TypeId MpTcpFileSendApplication::GetTypeId(void) {
        static TypeId tid =
            TypeId("ns3::MpTcpFileSendApplication")
                .SetParent<Application>()
                .AddConstructor<MpTcpFileSendApplication>()
                // .AddAttribute("SendSize",
                //               "The amount of data to send each time from application buffer to "
                //               "socket buffer.",
                //               UintegerValue(1000000),
                //               MakeUintegerAccessor(&MpTcpFileSendApplication::m_sendSize),
                //   MakeUintegerChecker<uint32_t>(1))
                .AddAttribute("BufferSize",
                              "The size of the application buffer.",
                              UintegerValue(1000000),
                              MakeUintegerAccessor(&MpTcpFileSendApplication::m_bufferSize),
                              MakeUintegerChecker<uint32_t>(1))
                .AddAttribute("Remote",
                              "The address of the destination",
                              AddressValue(),
                              MakeAddressAccessor(&MpTcpFileSendApplication::m_peer),
                              MakeAddressChecker())
                // .AddAttribute("MaxBytes",
                //               "The total number of bytes to send. "
                //               "Once these bytes are sent, "
                //               "no data is sent again. The value zero means "
                //               "that there is no limit.",
                //               UintegerValue(1000000), // 1 MB default of data to send
                //               MakeUintegerAccessor(&MpTcpFileSendApplication::m_maxBytes),
                //               MakeUintegerChecker<uint32_t>())
                .AddAttribute("Protocol",
                              "The type of protocol to use.",
                              TypeIdValue(TcpSocketFactory::GetTypeId()),
                              MakeTypeIdAccessor(&MpTcpFileSendApplication::m_tid),
                              MakeTypeIdChecker())
                .AddTraceSource("Tx",
                                "A new packet is created and is sent",
                                MakeTraceSourceAccessor(&MpTcpFileSendApplication::m_txTrace),
                                "ns3::Packet::TracedCallback")
                .AddAttribute("FilePath",
                              "path of transmit file",
                              StringValue(),
                              MakeStringAccessor(&MpTcpFileSendApplication::m_filePath),
                              MakeStringChecker());
        return tid;
    }

    MpTcpFileSendApplication::MpTcpFileSendApplication()
        : m_socket(nullptr),
          m_connected(false),
          m_totBytes(0) {
        NS_LOG_FUNCTION(this);
        m_data = new uint8_t[m_bufferSize];
    }

    MpTcpFileSendApplication::~MpTcpFileSendApplication() {
        NS_LOG_FUNCTION(this);
        delete[] m_data;
        m_data = 0;
    }

    void MpTcpFileSendApplication::SetBuffer(uint32_t buffSize) {
        NS_LOG_FUNCTION_NOARGS();
        delete[] m_data;
        m_data = 0;
        m_data = new uint8_t[buffSize];
    }

    Ptr<Socket> MpTcpFileSendApplication::GetSocket(void) const {
        NS_LOG_FUNCTION(this);
        return m_socket;
    }

    void MpTcpFileSendApplication::DoDispose(void) {
        NS_LOG_FUNCTION(this << "@" << Simulator::Now().GetSeconds() << "s");
        m_socket = nullptr;
        Application::DoDispose(); // chain up
    }

    // Application Methods
    void MpTcpFileSendApplication::StartApplication(void) // Called at time specified by Start
    {
        NS_LOG_FUNCTION(this);
        NS_LOG_DEBUG("Node: " << GetNode()->GetId() << "Remote: " << m_peer);
        // Create the socket if not already
        if (!m_socket) {
            m_socket = CreateObject<MpTcpSocketBase>(
                GetNode()); // m_socket = Socket::CreateSocket (GetNode (), m_tid);
            m_socket->Bind();
            int result = m_socket->Connect(m_peer);
            if (result == 0) {
                m_socket->SetConnectCallback(
                    MakeCallback(&MpTcpFileSendApplication::ConnectionSucceeded, this),
                    MakeCallback(&MpTcpFileSendApplication::ConnectionFailed, this));
                m_socket->SetDataSentCallback(
                    MakeCallback(&MpTcpFileSendApplication::DataSend, this));
                // m_socket->SetSendCallback(MakeCallback(&MpTcpBulkSendApplication::DataSend,
                // this));
            } else {
                // NS_LOG_ERROR("Connection is failed");
                NS_FATAL_ERROR("Connection is failed");
            }
        }
        if (m_connected) {
            NS_ASSERT(this->m_filePath != "");
            this->m_bufController = BufferController{{this->m_filePath}};
            SendFile();
        }
    }

    void MpTcpFileSendApplication::StopApplication(void) // Called at time specified by Stop
    {
        NS_LOG_FUNCTION(this);

        if (m_socket != nullptr) {
            m_socket->Close();
            m_connected = false;
        } else {
            NS_LOG_WARN("MpTcpFileSendApplication found null socket to close in StopApplication");
        }
    }

    // Private helpers
    void MpTcpFileSendApplication::SendFile(void) {
        NS_LOG_FUNCTION(this);
        // size_t txAvailable = m_socket->GetTxAvailable();
        NS_LOG_DEBUG("m_totBytes: " << m_totBytes
                                    << " GetTxAvailable: " << m_socket->GetTxAvailable());

        while (!this->m_bufController.isEnd() &&
               m_socket->GetTxAvailable()) { // Time to send more new data into MPTCP socket buffer

            // uint32_t tmp = std::min(m_sendSize, m_maxBytes - m_totBytes);
            // uint32_t toSend = std::min(tmp, m_socket->GetTxAvailable());
            uint32_t toSend = m_socket->GetTxAvailable();

            // int actual = m_socket->FillBuffer(&m_data[m_totBytes], toSend);
            Buffer stuffing = this->m_bufController.Read(toSend);
            size_t read_size = stuffing.GetSize();
            std::vector<uint8_t> _buf(read_size);
            stuffing.CopyData(_buf.data(), read_size);
            int actual = m_socket->FillBuffer(_buf.data(), read_size);
            m_totBytes += actual;
            NS_LOG_DEBUG("toSend: " << toSend << " actual: " << actual
                                    << " totalByte: " << m_totBytes);
            // NS_LOG_UNCOND("send time " << Simulator::Now().As(Time::MS));
        }
        m_socket->SendBufferedData();

        if (this->m_bufController.isEnd() && m_connected) {
            NS_LOG_DEBUG("SendData is ended!");
            m_socket->Close();
            m_connected = false;
        }
    }

    void MpTcpFileSendApplication::ConnectionSucceeded(Ptr<Socket> socket) {
        NS_LOG_FUNCTION(this << socket);
        NS_LOG_LOGIC("MpTcpFileSendApplication Connection succeeded");
        m_connected = true;
        NS_ASSERT(this->m_filePath != "");
        this->m_bufController = BufferController{{this->m_filePath}};
        SendFile();
    }

    void MpTcpFileSendApplication::ConnectionFailed(Ptr<Socket> socket) {
        NS_LOG_FUNCTION(this << socket);
        NS_LOG_LOGIC("MpTcpFileSendApplication, Connection Failed");
    }

    void MpTcpFileSendApplication::DataSend(Ptr<Socket>, uint32_t) {
        NS_LOG_FUNCTION(this);

        if (m_connected) { // Only send new data if the connection has completed
            Simulator::ScheduleNow(&MpTcpFileSendApplication::SendFile, this);
        }
    }

} // Namespace ns3
