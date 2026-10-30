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

#ifndef MP_TCP_FILE_SINK_H
#define MP_TCP_FILE_SINK_H

#include "fdt.h"

#include "ns3/address.h"
#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/mp-tcp-socket-base.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"

namespace ns3 {

    class Address;
    class Socket;
    class Packet;

    class MpTcpFileSink : public Application {
      public:
        static TypeId GetTypeId(void);
        MpTcpFileSink();

        virtual ~MpTcpFileSink();

        // Return the total bytes received in this sink app
        uint32_t GetTotalRx() const;
        Ptr<MpTcpSocketBase> getMpTcpSocket();

      protected:
        virtual void DoDispose(void);

      private:
        // void
        // Inherited from Application base class.
        virtual void StartApplication(void); // Called at time specified by Start
        virtual void StopApplication(void);  // Called at time specified by Stop

        void HandleRead(Ptr<Socket>);
        void HandleAccept(Ptr<Socket>, const Address& from);
        void HandlePeerClose(Ptr<Socket>);
        void HandlePeerError(Ptr<Socket>);

        void MergeChunck(std::string filename, uint8_t chunck_num);

        bool ReceiveFile(Buffer::Iterator& out); // return byte

        enum hash_algo : uint8_t {
            sha_256 = 0,
            md5
        };

        // bool GetCheckSum(hash_algo, Buffer data);

        Ptr<MpTcpSocketBase> m_socket;       // Listening socket
        std::list<Ptr<Socket>> m_socketList; // the accepted sockets

        Address m_local;             // Local address to bind to
        uint32_t m_totalRx;          // Total bytes received
        TypeId m_tid;                // Protocol TypeId
        std::string m_bufExportFile; //!< file to export rx buffer
        uint32_t size;
        std::string m_exportBaseDirStr;
        std::vector<std::pair<std::string, uint8_t>> m_mergeList; // <filename, chunck_num>
        uint32_t m_timeout;
        bool m_fdtReceived;
        FileDescriptor m_destFdt;
        ofstream m_export;
        // uint8_t    *buf;
        TracedCallback<Ptr<const Packet>, const Address&> m_rxTrace;
    };

} // namespace ns3

#endif // MP_TCP_FILE_SINK_H
