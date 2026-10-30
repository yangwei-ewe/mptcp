/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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
 */

#ifndef MPTCP_FILE_SEND_APPLICATION_H
#define MPTCP_FILE_SEND_APPLICATION_H

#include "fdt.h"

#include "ns3/address.h"
#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/mp-tcp-socket-base.h"
#include "ns3/ptr.h"
#include "ns3/string.h"
#include "ns3/traced-callback.h"

#include <fstream>

/*
With reference to HTTP, we define a simple L7 file transfer protocol. The protocol format is as
follows:

1. Header

The header consists of key-value pairs. Each pair is separated by a newline, and the header is
terminated by an additional newline.

Only the following keys are accepted in the current version of the protocol:

a. stat: A literal string that MUST be either "file" or "close". The protocol allows multiple files
to be transmitted over a single connection. The "file" value indicates the start of a new file,
while the "close" value indicates the end of the connection.

b. filename: The name of the file being transmitted. The value is a raw string.

c. checksum: The checksum of the file when chunk_id and chunk_num are not specified; otherwise, the
checksum of the corresponding chunk. The value is a string.

d. chunk_id (optional): The identifier of the chunk. The value is a uint8_t. This field is optional.
If it is not specified, the file is transmitted as a whole.

e. chunk_num (optional): The total number of chunks. The value is a uint16_t. This field is
optional. If it is not specified, the file is transmitted as a whole.

chunk_id and chunk_num MUST either both be specified or both be omitted. If only one of these fields
is specified, the packet SHOULD be treated as containing the whole file.

f. bytes: The length of the payload in bytes. The value is a uint64_t.

2. Payload

The payload immediately follows the header after the terminating newline. The length of the payload
MUST be specified by the bytes field in the header.
*/

/*
*header*
stat:file
filename: str
checksum: str
chunk_id: uint8_t
chunk_num: uint8_t
bytes: uint64_t

*payload*
*/

/*
*header*
stat: close
*/

namespace ns3 {

    class Address;
    class Socket;
    class MpTcpSocketBase;

    // enum fdt_stat : uint8_t {
    //     file = 0,
    //     close
    // };

    // struct FileDescriptor {
    //     fdt_stat stat;
    //     std::string filename;
    //     size_t filesize;
    //     std::string checksum;
    //     uint8_t chunck_id;
    //     uint8_t chunck_num;
    //     uint64_t start_from;
    //     size_t byte;
    // };

    class Controler {
      protected:
        FileDescriptor _fdt;
        size_t offset;

      public:
        // Controler(fdt);
        virtual Buffer Read(size_t len) = 0;
        virtual bool isEnd() const = 0;
        Controler(FileDescriptor _fdt);
    };

    class HeaderControler : public Controler {
      private:
        std::string header;

      public:
        HeaderControler(FileDescriptor _fdt);
        Buffer Read(size_t len);
        bool isEnd() const;
    };

    class FileControler : public Controler {
      private:
        std::ifstream fd;
        std::streampos fileEnd;

      public:
        Buffer Read(size_t len);
        FileControler(FileDescriptor _fdt);
        bool isEnd() const;
    };

    class BufferController {
      private:
        std::vector<std::shared_ptr<Controler>> sendQueue;

      public:
        BufferController(const ns3::StringVector& fileList);
        BufferController() = default;
        Buffer Read(size_t len);
        bool isEnd() const;
    };

    class MpTcpFileSendApplication : public Application {
      public:
        /**
         * \brief Get the type ID.
         * \return the object TypeId
         */
        static TypeId GetTypeId(void);

        MpTcpFileSendApplication();

        virtual ~MpTcpFileSendApplication();

        /**
         * \brief Get the socket this application is attached to.
         * \return pointer to associated socket
         */
        Ptr<Socket> GetSocket(void) const;

        void SetBuffer(uint32_t buffSize);

      protected:
        virtual void DoDispose(void);

      private:
        // inherited from Application base class.
        virtual void StartApplication(void); // Called at time specified by Start
        virtual void StopApplication(void);  // Called at time specified by Stop
        /**
         * \brief Send data until the L4 transmission buffer is full.
         */
        void SendFile();

        // Ptr<Socket>     m_socket;       //!< Associated socket
        Ptr<MpTcpSocketBase> m_socket;
        Address m_peer;   //!< Peer address
        bool m_connected; //!< True if connected
        // uint32_t m_sendSize;                         //!< Size of data to send each time
        uint32_t m_totBytes;                         //!< Total bytes sent so far
        TypeId m_tid;                                //!< The type of protocol to use.
        uint8_t* m_data;                             // Application Buffer
        uint32_t m_bufferSize;                       // Application buffer size
        TracedCallback<Ptr<const Packet>> m_txTrace; // Traced Callback: sent packets
        // ifstream m_fd;                               //!< file to transmit
        // std::vector<FileDescriptor> m_sendFileList; //!< list of files to transmit
        std::string m_filePath;
        BufferController m_bufController;

      private:
        /**
         * \brief Connection Succeeded (called by Socket through a callback)
         * \param socket the connected socket
         */
        void ConnectionSucceeded(Ptr<Socket> socket);
        /**
         * \brief Connection Failed (called by Socket through a callback)
         * \param socket the connected socket
         */
        void ConnectionFailed(Ptr<Socket> socket);
        /**
         * \brief Send more data as soon as some has been transmitted.
         */
        void DataSend(Ptr<Socket>, uint32_t); // for socket's SetSendCallback
    };

} // namespace ns3

#endif /* MPTCP_FILE_SEND_APPLICATION_H */
