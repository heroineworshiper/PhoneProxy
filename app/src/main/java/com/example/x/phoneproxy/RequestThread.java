/*
 * PhoneProxy
 * Copyright (C) 2020-2025 Adam Williams <broadcast at earthling dot net>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU 1General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 */

// handle certain requests asynchronously

package com.example.x.phoneproxy;
import android.util.Log;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Semaphore;





// handle an asynchronous request
public class RequestThread extends Thread
{
    ServerThread server;
    boolean busy = false;
    Semaphore lock = new Semaphore(0);
    byte[] packet = new byte[Server.BUFSIZE];
    int packet_size;

    public RequestThread(ServerThread server)
    {
        this.server = server;
        start();
    }

    public void handlePacket(byte[] packet, 
        int packet_size)
    {
        this.packet_size = packet_size;
        System.arraycopy(packet, 0, this.packet, 0, packet_size);
        busy = true;
        lock.release();
    }

    public void do_icmp()
    {
        try{
// ICMP request
            int total_length = Math2.read_uint16be(packet, 2);
            Log.i("RequestThread", "do_icmp: total_length=" + total_length + " packet_size=" + packet_size);
            int ttl = packet[8];
            InetAddress src = Math2.read_address(packet, 12);
            InetAddress dst = Math2.read_address(packet, 16);
            int sequence = Math2.read_uint16be(packet, 26);

// forward to phone
            Log.i("RequestThread", "do_icmp: forwarding ICMP to " + dst.toString());
            if(dst.isReachable(1000))
// DEBUG: fake it
//                        if(true)
            {
// Send reply packet to client
                Log.i("RequestThread", "do_icmp: ICMP success");
// swap the addresses
                Math2.write_address(packet, 12, dst);
                Math2.write_address(packet, 16, src);
                packet[8] = (byte)(ttl - 1);
// reset header chksum
                packet[10] = 0;
                packet[11] = 0;
// start of ICMP.  reply code
                packet[20] = 0x00;
// ICMP chksum
                packet[22] = 0;
                packet[23] = 0;

// payload chksum
                int sum = Math2.chksum(packet, Server.IP_HEADER_SIZE, total_length - Server.IP_HEADER_SIZE);
                Math2.write_uint16be(packet, 22, sum);

// header chksum
                sum = Math2.chksum(packet, 0, Server.IP_HEADER_SIZE);
                Math2.write_uint16be(packet, 10, sum);
                server.writeClient(packet, 0, packet_size);
                Log.i("RequestThread", "do_icmp: wrote " + packet_size + " bytes");
            }
            else
            {
                Log.i("RequestThread", "do_icmp: " + dst.toString() + " not reachable");
            }
        } catch(Exception e)
        {
            Log.i("x", "RequestThread.do_icmp: " + e);
        }
    }

    public void do_dns()
    {
// extract the hostname
        int ttl = packet[8];
        int total_size = Math2.read_uint16be(packet, 2);
        int offset = 40;
        StringBuilder sb = new StringBuilder();
        while(true)
        {
            int size = packet[offset];
            offset += 1;
            if(size == 0) break;

            String subString = new String(packet, offset, size, StandardCharsets.UTF_8);
            offset += size;
            if(sb.length() > 0) sb.append(".");
            sb.append(subString);
        }

        int type_ = Math2.read_uint16be(packet, offset);
        offset += 2;
        int class_ = Math2.read_uint16be(packet, offset);
        offset += 2;

//            Log.i("x", "RequestThread.do_dns name=" + sb.toString() + 
//                " type=" + type_);

        final int TYPE_A = 0x01;
        final int TYPE_AAAA = 0x1c;
        final int TYPE_PTR = 0x0c;
        final int TYPE_MX = 0x0f;
        if(type_ == TYPE_A ||  // A
            type_ == TYPE_AAAA ||  // AAAA
            type_ == TYPE_PTR || // PTR
            type_ == TYPE_MX) // MX
        {
            InetAddress[] addresses = null;

            if(type_ == TYPE_A)
            {
                try
                {
                    addresses = Inet4Address.getAllByName(sb.toString());
                } catch(Exception e)
                {
                }
            }

            int total_results = 0;
            if(addresses != null && addresses.length > 0)
            {
                for (InetAddress i : addresses)
                {
//                        Log.i("x", "RequestThread.do_dns address=" + i.toString());
                    if(i instanceof Inet4Address)
                        total_results++;
                }
            }

// construct response packet
            int total_size2 = total_size;

// shortened domane names to reduce the bandwidth & because
// some host queries failed with longer domane names
            final byte[] dummy_aaaa = {
                (byte)0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 
// data length
                0x00, 0x1a,
//                        0x00, 0x2f, 

// name server
                0x01, 0x78, 0x00,
//                        0x03, 0x6e, 0x73, 0x31,
//                        0x06, 0x61, 0x66, 0x72, 0x61, 0x69, 0x64, 0x03, 0x6f, 0x72, 0x67, 0x00, 

// mailbox
                0x01, 0x78, 0x00,
//                        0x08, 0x64, 0x6e, 0x73,
//                        0x61, 0x64, 0x6d, 0x69, 0x6e, (byte)0xc0, 0x34, 


// serial number
                (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
// stuff
                0x00, 0x01, 0x51, (byte)0x80, 0x00,
                0x00, 0x1c, 0x20, 0x00, 0x24, (byte)0xea, 0x00, 0x00, 0x00, 0x0e, 0x10
            };
            final byte[] dummy_ptr = {
                (byte)0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x38, 0x40, 
// hostname length
                0x00, 0x03, 
//                        0x00, 0x17, 
// the hostname
                0x01, 0x78, 0x00
//                            0x05, 0x76, 0x68, 0x6f, 0x73, 0x74, 
//                            0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x66, 0x6f, 0x72, 0x67, 0x65, 
//                            0x03, 0x6e, 0x65, 0x74, 0x00                                       
            };
            final byte[] dummy_mx = {
                (byte)0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 
// hostname length + preference
                0x00, 0x05, 
// preference
                0x00, 0x0a, 

// hostname
                0x01, 0x78, 0x00
//                        0x05, 0x75,
//                        0x73, 0x65, 0x72, 0x73, 0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x66, 0x6f, 0x72, 0x67, 0x65,
//                        0x03, 0x6e, 0x65, 0x74, 0x00
            };

            final byte[] dummy_fail = {
                (byte)0xc0, 0x32, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x03, (byte)0x84, 0x00, 0x3d, 0x01, 0x61, 0x0c, 0x67,
                0x74, 0x6c, 0x64, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00,
                0x05, 0x6e, 0x73, 0x74, 0x6c, 0x64, 0x0c, 0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2d,
                0x67, 0x72, 0x73, (byte)0xc0, 0x32, 0x69, 0x11, (byte)0x90, (byte)0xae, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x03,
                (byte)0x84, 0x00, 0x09, 0x3a, (byte)0x80, 0x00, 0x00, 0x03, (byte)0x84
            };


            switch(type_)
            {
                case TYPE_A: 
                    if(total_results > 0)
                        total_size2 += 16 * total_results;
//                        else
//                            total_size2 += dummy_fail.length;
                    break;
                case TYPE_AAAA: 
                    total_size2 += dummy_aaaa.length; 
                    break;
                case TYPE_PTR: 
                    total_size2 += dummy_ptr.length; 
                    break;
                case TYPE_MX:
                default:
                    total_size2 += dummy_mx.length;
                    break;
            }

            Math2.write_uint16be(packet, 2, total_size2);
            packet[8] = (byte)(ttl - 1);
// reset header chksum
            packet[10] = 0;
            packet[11] = 0;
            InetAddress src = Math2.read_address(packet, 12);
            InetAddress dst = Math2.read_address(packet, 16);
            int srcPort = Math2.read_uint16be(packet, 20);
            int dstPort = Math2.read_uint16be(packet, 22);
// swap the addresses
            Math2.write_address(packet, 12, dst);
            Math2.write_address(packet, 16, src);
            Math2.write_uint16be(packet, 20, dstPort);
            Math2.write_uint16be(packet, 22, srcPort);
            Math2.write_uint16be(packet, 24, total_size2 - Server.IP_HEADER_SIZE);
// reset UDP chksum
            packet[26] = 0;
            packet[27] = 0;
// reply code
            Math2.write_uint16be(packet, 30, 0x8180);
// A record
            if(type_ == TYPE_A)
            {
                if(total_results == 0)
                {
// failure code
                    Math2.write_uint16be(packet, 30, 0x8183);
// authority count
                    Math2.write_uint16be(packet, 36, 0x0000);

// undocumented NAME code has to be computed from the hostname
//                        Math2.write_uint16be(packet, 36, 0x0001);
// append dummy result
//                        System.arraycopy(dummy_fail, 0, packet, total_size, dummy_fail.length);
//                        Random random = new Random();
// serial number
//                        Math2.write_uint32be(packet, total_size2 - 20, random.nextInt());
                }
                else
                {
// answer count
                    Math2.write_uint16be(packet, 34, total_results);
// append results
                    offset = total_size;
                    for (InetAddress i : addresses)
                    {
                        if(i instanceof Inet4Address)
                        {
                            packet[offset++] = (byte)0xc0;
                            packet[offset++] = (byte)0x0c;
                            Math2.write_uint16be(packet, offset, type_);
                            offset += 2;
                            Math2.write_uint16be(packet, offset, class_);
                            offset += 2;
                            Math2.write_uint32be(packet, offset, 3600);
                            offset += 4;
                            Math2.write_uint16be(packet, offset, 4);
                            offset += 2;
                            Math2.write_address(packet, offset, i);
                            offset += 4;
                        }
                    }
                }
            }
            else
// AAAA record
            if(type_ == TYPE_AAAA)
            {
// authority count
                Math2.write_uint16be(packet, 36, 0x0001);
// append dummy result
                System.arraycopy(dummy_aaaa, 0, packet, total_size, dummy_aaaa.length);
            }
            else
// PTR record
            if(type_ == TYPE_PTR)
            {
// answer count
                Math2.write_uint16be(packet, 34, 0x0001);
// append dummy result
                System.arraycopy(dummy_ptr, 0, packet, total_size, dummy_ptr.length);
// append real PTR record with the original domane name.
// would have to manetain a table of DNS queries
//                         Math2.write_uint16be(packet, total_size, 0xc00c);
//                         Math2.write_uint16be(packet, total_size + 2, type_);
//                         Math2.write_uint16be(packet, total_size + 4, class_);
//                         Math2.write_uint32be(packet, total_size + 4, 14400);
//                         Math2.write_uint16be(packet, total_size + 4, );

            }
            else
            if(type_ == TYPE_MX)
            {
// answer count
                Math2.write_uint16be(packet, 34, 0x0001);
// append dummy result
                System.arraycopy(dummy_mx, 0, packet, total_size, dummy_mx.length);
            }

// header chksum
            int sum = Math2.chksum(packet, 0, Server.IP_HEADER_SIZE);
            Math2.write_uint16be(packet, 10, sum);
// UDP chksum
            byte[] pseudo_hdr = new byte[12];
            Math2.write_address(pseudo_hdr, 0, dst);
            Math2.write_address(pseudo_hdr, 4, src);
            pseudo_hdr[8] = 0;
            pseudo_hdr[9] = Server.PROTO_UDP; // protocol
            Math2.write_uint16be(pseudo_hdr, 10, total_size2 - Server.IP_HEADER_SIZE);
            sum = Math2.chksum2(0, pseudo_hdr, 0, pseudo_hdr.length);
            sum = Math2.chksum2(sum, packet, Server.IP_HEADER_SIZE, total_size2 - Server.IP_HEADER_SIZE);

            if(sum == 0) sum = 0xffff;
            sum ^= 0xffff;

            Math2.write_uint16be(packet, 26, sum);
            server.writeClient(packet, 0, total_size2);
        }
    }

    public void do_tcp(ServerThread server)
    {
        int total_size = Math2.read_uint16be(packet, 2);
        InetAddress src = Math2.read_address(packet, 12);
        InetAddress dst = Math2.read_address(packet, 16);
        int srcPort = Math2.read_uint16be(packet, 20);
        int dstPort = Math2.read_uint16be(packet, 22);
        int flags = Math2.read_uint16be(packet, 32);

        if((flags & 0x0fff) == 0x0002)
        {
// SYN/connect from phone.  Create a new TCPThread
            boolean gotIt = false;
            TCPThread thread = null;
            synchronized(server)
            {
                server.clear_tcp_threads(src,
                    dst,
                    srcPort,
                    dstPort);

                for(int i = 0; i < Server.TOTAL_TCP; i++)
                {
                    if(server.tcp_threads[i] == null)
                    {
                        server.tcp_threads[i] = new TCPThread(server, i);
// create new real connection
                        boolean result = server.tcp_threads[i].connect(src,
                            dst,
                            srcPort,
                            dstPort);
                        if(!result)
                        {
                            gotIt = true;
                            thread = server.tcp_threads[i];
                        }
                        else
                        {
                            server.tcp_threads[i] = null;
                        }
                        break;
                    }
                }



            } // synchronized

            Math2.write_address(packet, 12, dst);
            Math2.write_address(packet, 16, src);
            Math2.write_uint16be(packet, 20, dstPort);
            Math2.write_uint16be(packet, 22, srcPort);

            if(gotIt)
            {
// window size not scaled in the SYN
                thread.windowSize = Math2.read_uint16be(packet, 34);
// get the options
                int offset = 40;
                while(offset < total_size)
                {
                    int kind = packet[offset++];
//                        Log.i("x", "RequestThread SYN offset=" + offset + " kind=" + kind);
                    int size = 0;
                    switch(kind)
                    {
                        case 2: // maximum segment size
                            size = packet[offset++];
                            thread.maxSegmentSize = Math2.read_uint16be(packet, offset);
                            offset += size - 2;
                            break;
                        case 4: // SACK permitted
                            size = packet[offset++];
                            offset += size - 2;
                            break;
                        case 3: // window scaler
                            size = packet[offset++];
//                                Log.i("x", "RequestThread SYN offset=" + offset + " windowScale=" + packet[offset]);
                            thread.windowScale = (1 << packet[offset++]);
                            offset += size - 3;
                            break;
                        case 8: // timestamps
                            size = packet[offset++];
                            offset += size - 2;
                            break;
                        case 1: // NOP
                        default:
                            break;
                    }
                }

// compute a window size from the window scale
                thread.myWindowSize = 1;
                while(thread.myWindowSize < 0x80000 &&
                    thread.myWindowSize / thread.windowScale < 65535)
                    thread.myWindowSize += thread.windowScale;

// send the SYN ACK
                Math2.write_uint16be(packet, 32, (flags & 0xf000) | 0x0012);
// the SYN ACK window size from wireshark
                Math2.write_uint16be(packet, 34, 0xffff);
// initialize the sequence numbers
// return client sequence number + 1 as the ack number
                thread.clientSequence0 = Math2.read_uint32be(packet, 24);
                thread.clientSequence += 1;
                Math2.write_uint32be(packet, 28, thread.getAbsClientSequence());
// return starting phone sequence number as the sequence number
                Math2.write_uint32be(packet, 24, thread.getAbsMySequence());
// increment to reflect ACK from client
                thread.mySequence += 1;

//                     Log.i("x", "RequestThread SYN windowSize=" + thread.windowSize +
//                         " windowScale=" + thread.windowScale);
                Log.i("x", "RequestThread.do_tcp SYN starting tcp_thread #" + thread.threadNumber + 
                    " windowSize=" + thread.windowSize + 
                    " myWindowSize=" + thread.myWindowSize + 
                    " windowScale=" + thread.windowScale + 
                    " " + src.toString() + 
                    ":" + srcPort + 
                    " -> " + dst.toString() + 
                    ":" + dstPort);
                int timestamp = Math2.read_int32be(packet, 48);
                Math2.write_uint32be(packet, 52, timestamp);
            }
            else
            {
// send the failure ACK
                int tcp_header_size = 20;
                total_size = Server.IP_HEADER_SIZE + tcp_header_size;
                Math2.write_uint16be(packet, 2, total_size);
                Math2.write_uint16be(packet, 32, Server.encodeTcpFlags(tcp_header_size, 0x0014));
                Math2.write_uint16be(packet, 34, 0); // window size
                long clientSequence = Math2.read_uint32be(packet, 24);
                clientSequence += 1;
                Math2.write_uint32be(packet, 24, 0); // my sequence number 0
                Math2.write_uint32be(packet, 28, (int)clientSequence); // ack number + 1
            }

            Server.tcp_chksum(packet, total_size);
            server.writeClient(packet, 0, total_size);
        }
    }

    public void run()
    {
        while(true)
        {
            try{
                lock.acquire();
            } catch(Exception e)
            {
                Log.i("x", "RequestThread.run: " + e);
            }

            if(packet[9] == Server.PROTO_ICMP &&
                packet[20] == 0x08) // request
            {
                do_icmp();
            }
            else
            if(packet[9] == Server.PROTO_UDP &&
                packet[22] == 0x00 && // DNS port
                packet[23] == 0x35) // DNS port
            {
// extract the hostname
                do_dns();
            }
            else
            if(packet[9] == Server.PROTO_TCP)
            {
                do_tcp(server);
            }

            busy = false;
            server.wait_request.release();
        }
    }
}








