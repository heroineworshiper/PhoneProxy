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


// state of every connection to the phone proxy
// forwards data from client to phone

package com.example.x.phoneproxy;


import android.util.Log;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.Semaphore;



public class ServerThread extends Thread
{
    public RequestThread request_threads[] = new RequestThread[Server.TOTAL_REQUESTS];
    public TCPThread tcp_threads[] = new TCPThread[Server.TOTAL_TCP];
// wait for a request thread to finish
    Semaphore wait_request = new Semaphore(0);

    boolean busy = false;
    Socket connection;
// to client
//    OutputStream out;
    BufferedOutputStream clientOut;
    Semaphore lock = new Semaphore(0);
    byte[] buffer = new byte[Server.BUFSIZE];
    byte[] packet = new byte[Server.BUFSIZE];

    public ServerThread()
    {
        start();
    }

    public void startConnection(Socket connection)
    {
        this.connection = connection;
        try{
            this.clientOut = new BufferedOutputStream(connection.getOutputStream());
        } catch(Exception e)
        {
        }
        busy = true;
        lock.release();
    }
    
    public void writeClient(byte[] data, int offset, int size)
    {
        synchronized(clientOut)
        {
            try {
                clientOut.write(data, offset, size);
                clientOut.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }

//             byte[] temp = new byte[4096];
//             int min_size = 1024;
//             int total_size = size;
//             System.arraycopy(data, offset, temp, 0, size); // the payload
//             if(size < min_size)
//             {
//                 total_size = min_size;
//                 Arrays.fill(temp, size, min_size, (byte)0xff);
//             }
//             try {
//                 clientOut.write(temp);
//                 clientOut.flush();
//             } catch (IOException e) {
//                 e.printStackTrace();
//             }
        }
    }

// synchronous TCP packets from client to phone
    public boolean do_tcp()
    {
        int flags = Math2.read_uint16be(packet, 32);
        boolean gotIt = false;
        int payload_size = 0;

        if((flags & 0x0010) == 0x0010)
        {
// ACK from client
            int psh = (flags & 0x0008);
            InetAddress src = Math2.read_address(packet, 12);
            InetAddress dst = Math2.read_address(packet, 16);
            int srcPort = Math2.read_uint16be(packet, 20);
            int dstPort = Math2.read_uint16be(packet, 22);
            TCPThread thread = get_tcp_thread(src,
                dst,
                srcPort,
                dstPort);
            if(thread != null)
            {
                int total_size = Math2.read_uint16be(packet, 2);
                int tcp_header_size = Server.decodeTcpSize(flags);
                int payload_offset = tcp_header_size + Server.IP_HEADER_SIZE;
// absolute client sequence to be sent in the ACK
                long clientSequence0 = Math2.read_uint32be(packet, 24);
// relative client sequence for sorting
                long clientSequence = thread.getClientSequence(clientSequence0);
                thread.windowSize = Math2.read_uint16be(packet, 34) *
                    thread.windowScale;
                boolean dup = false;
                payload_size = total_size - payload_offset;


                if(payload_size > 0)
                {
// sort the packets
                    if(thread.clientSequence > clientSequence)
                    {
// already sent to phone
                        Log.i("ServerThread", "do_tcp #" + thread.threadNumber + 
                            " got a dup.  thread.clientSequence=" + thread.clientSequence +
                            " clientSequence=" + clientSequence);
                    }
                    else
                    if(thread.clientSequence == clientSequence)
                    {
// got next contiguous packet
// so rarely happens, it's not worth aggregating all the fragments in a single write
                        try{
                            thread.phoneOut.write(packet, payload_offset, payload_size);
                            thread.phoneOut.flush();
                        } catch(Exception e)
                        {
                        }
                        thread.clientSequence += payload_size;


// search buffered payloads for more contiguous packets
                        boolean done = false;
                        while(!done)
                        {
                            done = true;

                            for(int i = 0; i < thread.payloads.size(); i++)
                            {
                                TCPPayload payload = thread.payloads.get(i);
                                if(payload.clientSequence == thread.clientSequence)
                                {
// forward payload to phone
                                    try{
                                        thread.phoneOut.write(payload.data, 0, payload.data.length);
                                        thread.phoneOut.flush();
                                    } catch(Exception e)
                                    {
                                    }
                                    thread.clientSequence += payload.data.length;
                                    thread.payloads.remove(i);
                                    i--;
                                    done = false;
                                }
                            }
                        }

//                         Log.i("ServerThread", "do_tcp #" + thread.threadNumber + 
//                             " got contiguous.  clientSequence=" + clientSequence +
//                             " total payloads=" + thread.payloads.size() + 
//                             " wrote " + output_size);
                    }
                    else
                    {
// future packet
                        Log.i("ServerThread", "do_tcp #" + thread.threadNumber + 
                            " got future.  thread.clientSequence=" + thread.clientSequence +
                            " clientSequence=" + clientSequence + 
                            " total payloads=" + thread.payloads.size());
                        boolean exists = false;
                        for(TCPPayload i : thread.payloads)
                        {
                            if(i.clientSequence == clientSequence)
                            {
                                exists = true;
                                break;
                            }
                        }
                        
                        if(!exists)
                        {
                            thread.payloads.add(new TCPPayload(clientSequence,
                                packet, 
                                payload_offset, 
                                payload_size));
                        }
                    }

// do this on the client to reduce wifi traffic
//                     if((flags & 0x0001) == 0)
//                     {
// // send the ACK if not also a FIN
// // no timestamps
//                         total_size = Server.IP_HEADER_SIZE + Server.TCP_HEADER_SIZE;
//                         Math2.write_uint16be(packet, 2, total_size);
//                         Math2.write_address(packet, 12, dst);
//                         Math2.write_address(packet, 16, src);
//                         Math2.write_uint16be(packet, 20, dstPort);
//                         Math2.write_uint16be(packet, 22, srcPort);
// 
//                         long mySequence = Math2.read_uint32be(packet, 28);
//                         clientSequence0 += payload_size;
//                         Math2.write_uint32be(packet, 24, (int)mySequence);
//                         Math2.write_uint32be(packet, 28, (int)clientSequence0);
//                         flags = Server.encodeTcpFlags(Server.TCP_HEADER_SIZE, 0x0010);
//                         Math2.write_uint16be(packet, 32, flags);
//                         Math2.write_uint16be(packet, 34, thread.myWindowSize / thread.windowScale);
//                         packet[40] = 0x01;
//                         packet[41] = 0x01;
// // no timestamps.  Get a RST if we send timestamps
//                         packet[42] = 0x01;
//                         packet[43] = 0x01;
// 
//                         Server.tcp_chksum(packet, total_size);
//                         writeClient(packet, 0, total_size);
//                     }
                }
            }
            gotIt = true;
        }

        if((flags & 0x0001) == 0x0001)
        {
// FIN/close from client
            int total_size = Math2.read_uint16be(packet, 2);
            InetAddress src = Math2.read_address(packet, 12);
            InetAddress dst = Math2.read_address(packet, 16);
            int srcPort = Math2.read_uint16be(packet, 20);
            int dstPort = Math2.read_uint16be(packet, 22);

// close the real connection
            TCPThread thread = get_tcp_thread(src,
                dst,
                srcPort,
                dstPort);
            if(thread != null)
            {
                Log.i("x", "ServerThread.do_tcp #" + thread.threadNumber + 
                    " client closed");
                thread.close();
// send FIN ACK from phone if connection was previously open
// no timestamps
                total_size = Server.IP_HEADER_SIZE + Server.TCP_HEADER_SIZE;
                Math2.write_uint16be(packet, 2, total_size);
                Math2.write_address(packet, 12, dst);
                Math2.write_address(packet, 16, src);
                Math2.write_uint16be(packet, 20, dstPort);
                Math2.write_uint16be(packet, 22, srcPort);
                long clientSequence0 = Math2.read_uint32be(packet, 24);
                long mySequence = Math2.read_uint32be(packet, 28);
                clientSequence0 += payload_size + 1;  // FIN with data
                Math2.write_uint32be(packet, 24, (int)mySequence);
                Math2.write_uint32be(packet, 28, (int)clientSequence0);
                Math2.write_uint16be(packet, 32, Server.encodeTcpFlags(Server.TCP_HEADER_SIZE, 0x0011));
                packet[40] = 0x01;
                packet[41] = 0x01;
// no timestamps.  Get a RST if we send timestamps
                packet[42] = 0x01;
                packet[43] = 0x01;
                Log.i("ServerThread", "do_tcp: wrote FIN ACK");
            }
            else
            {
// send ACK from phone if connection was previously closed
// no timestamps
                total_size = Server.IP_HEADER_SIZE + Server.TCP_HEADER_SIZE;
                Math2.write_uint16be(packet, 2, total_size);
                Math2.write_address(packet, 12, dst);
                Math2.write_address(packet, 16, src);
                Math2.write_uint16be(packet, 20, dstPort);
                Math2.write_uint16be(packet, 22, srcPort);
                long clientSequence0 = Math2.read_uint32be(packet, 24);
                long mySequence = Math2.read_uint32be(packet, 28);
                clientSequence0 += 1;
                Math2.write_uint32be(packet, 24, (int)mySequence);
                Math2.write_uint32be(packet, 28, (int)clientSequence0);
                Math2.write_uint16be(packet, 32, Server.encodeTcpFlags(Server.TCP_HEADER_SIZE, 0x0010));
                packet[40] = 0x01;
                packet[41] = 0x01;
// no timestamps.  Get a RST if we send timestamps
                packet[42] = 0x01;
                packet[43] = 0x01;
                Log.i("ServerThread", "do_tcp: wrote ACK 2");
            }



// do this on the client to reduce wifi traffic
            Server.tcp_chksum(packet, total_size);
            writeClient(packet, 0, total_size);


            gotIt = true;
        }


        return gotIt;
    }


    void handlePacket(int size)
    {
        if(size >= Server.IP_HEADER_SIZE &&  // complete IPv4 header
            packet[8] > 1) // TTL
        {
// Full IPv4 header
            if(packet[9] == Server.PROTO_ICMP ||
                packet[9] == Server.PROTO_UDP ||
                packet[9] == Server.PROTO_TCP)
            {

// handle these synchronously
                boolean gotIt = false;
                if(packet[9] == Server.PROTO_TCP)
                {
                    gotIt = do_tcp();
                }

// handle it asynchronously
                if(!gotIt)
                {
                    RequestThread thread = null;
                    while(thread == null)
                    {
                        synchronized(this)
                        {
                            for(int i = 0; i < Server.TOTAL_REQUESTS; i++)
                            {
                                if(request_threads[i] == null)
                                    request_threads[i] = new RequestThread(this);

                                if(!request_threads[i].busy)
                                {
                                    thread = request_threads[i];
                                    thread.handlePacket(packet, size);
//                                        Log.i("x", "ServerThread.handlePacket starting request_thread #" + i);
                                    break;
                                }
                            }
                        }

                        if(thread == null)
                        {
// wait for a thread to finish
                            try {
                                wait_request.acquire();
                            } catch(Exception e)
                            {
                            }
                        }
                    }
                }
            }
        }
    }




    public TCPThread get_tcp_thread(InetAddress src,
        InetAddress dst,
        int srcPort,
        int dstPort)
    {
        for(int i = 0; i < Server.TOTAL_TCP; i++)
        {
            if(tcp_threads[i] != null &&
                tcp_threads[i].busy &&
                tcp_threads[i].compare(src,
                dst,
                srcPort,
                dstPort))
            {
                return tcp_threads[i];
            }
        }
        return null;
    }

    public void clear_tcp_threads(InetAddress src,
        InetAddress dst,
        int srcPort,
        int dstPort)
    {
        for(int i = 0; i < Server.TOTAL_TCP; i++)
        {
            if(tcp_threads[i] != null &&
                (!tcp_threads[i].busy ||
                tcp_threads[i].compare(src,
                    dst,
                    srcPort,
                    dstPort)))
            {
//                 Log.i("x", "Server.clear_tcp_threads tcp_thread #" + i + 
//                     " " + tcp_threads[i].src.toString() + 
//                     ":" + tcp_threads[i].srcPort + 
//                     " -> " + tcp_threads[i].dst.toString() + 
//                     ":" + tcp_threads[i].dstPort + 
//                     " " + (!tcp_threads[i].busy ? " idle" : " duplicate"));
                tcp_threads[i].close();
                tcp_threads[i] = null; // must clear to restart it
            }
        }
    }

    public void run()
    {
        while(true)
        {
            try {
// wait for the next connection
                lock.acquire();
            } catch(Exception e)
            {
            }

			Log.i("ServerThread", "run: new connection");

            BufferedInputStream in = null;
//            InputStream in = null;
            try {
                in = new BufferedInputStream(connection.getInputStream());
//                in = connection.getInputStream();
            } catch(Exception e)
            {
            }
            int packetSize = 0;
            int packetOffset = 0;

// read from the client.  Does not align on packets
            while(true)
            {
                int read_result = 0;

                try {
                    read_result = in.read(buffer, 0, buffer.length);
                } catch(Exception e)
                {
                    Log.i("ServerThread", "run: read fail");
                    e.printStackTrace();
                }

                if(read_result <= 0) break;
//                    Log.i("ServerThread", "run: got " + read_result + " bytes");

                for(int i = 0; i < read_result; i++)
                {
                    if(packetOffset == 0)
                    {
// got start code
                        if(buffer[i] == 0x45)
                        {
                            packet[packetOffset++] = buffer[i];
                        }
                    }
                    else
                    if(packetOffset < 4)
                    {
                        packet[packetOffset++] = buffer[i];
// got size
                        if(packetOffset >= 4)
                            packetSize = Math2.read_uint16be(packet, 2);
                    }
                    else
                    {
                        packet[packetOffset++] = buffer[i];
// got complete packet
                        if(packetOffset >= packetSize)
                        {
                            handlePacket(packetSize);
                            packetSize = 0;
                            packetOffset = 0;
                        }
                    }
                }
            }


            Log.i("x", "ServerThread.run: finished");
            if (connection != null)
            {
                try {
                    connection.close();
                } catch(Exception e)
                {
                }
            }

            busy = false;
        }
    }
}




