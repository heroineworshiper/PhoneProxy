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


// state of each TCP connection
// forwards data from phone to client

package com.example.x.phoneproxy;


import android.util.Log;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.BufferedInputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;



public class TCPThread extends Thread
{
    ServerThread server;
    InetAddress src = null;
    InetAddress dst = null;
    int srcPort = 0;
    int dstPort = 0;
    int id;
    int threadNumber = 0;
    boolean busy = false;
// send a FIN when exiting
    boolean sendFIN = true;
    Socket socket = null;
// from phone
    BufferedInputStream phoneIn;
// to phone
//    OutputStream out;
    BufferedOutputStream phoneOut;
// absolute starting sequence number from the phone
    long mySequence0;
// relative sequence number from the phone
    long mySequence;
// absolute starting sequence number from the client
    long clientSequence0 = 0;
// last contiguous relative sequence number from the client
    long clientSequence = 0;
    int prevPayload = 0;
// window size reported by the client
    int windowSize = 0;
// window size calculated by the phone
    int myWindowSize = 0;
    int windowScale = 1;
    int maxSegmentSize = 0;

    List<TCPPayload> payloads = new ArrayList<>();

    public TCPThread(ServerThread server, int threadNumber)
    {
        this.server = server;
        this.threadNumber = threadNumber;
    }

// compute the absolute sequence number from the starting absolute
// & relative numbers
    public int getAbsClientSequence()
    {
        long result = clientSequence0 + clientSequence;
        return (int)(result & 0xffffffffL);
    }

    public int getAbsMySequence()
    {
        long result = mySequence0 + mySequence;
        return (int)(result & 0xffffffffL);
    }

// compute a new relative sequence number from an absolute
// sequence number
    public long getClientSequence(long newClientSequence)
    {
        long result = 0;
        if(newClientSequence >= clientSequence0)
            result = newClientSequence - clientSequence0;
        else
            result = newClientSequence + 0xffffffffL - clientSequence0;
        return result;
    }

// return true if a match
    public boolean compare(InetAddress src,
        InetAddress dst,
        int srcPort,
        int dstPort)
    {
        if(src == null || dst == null) return false;
        return srcPort == this.srcPort &&
            dstPort == this.dstPort &&
            src.equals(this.src) &&
            dst.equals(this.dst);
    }

// returns true if it failed to connect
    public boolean connect(InetAddress src,
        InetAddress dst,
        int srcPort,
        int dstPort)
    {
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.src = src;
        this.dst = dst;

// create connection to phone
        boolean error = false;
        try{
            socket = new Socket(dst, dstPort);
        } catch(IOException e)
        {
            Log.i("TCPThread", "connect #" + threadNumber + 
                " " + getTitle() + 
                " connect failed");
            error = true;
        }

        if(!error)
        {
            Random random = new Random();
            mySequence0 = random.nextInt();
            id = random.nextInt();
            try {
                socket.setTcpNoDelay(true);
            } catch (SocketException e) {
                e.printStackTrace();
            }

// start reading
            try{
                phoneIn = new BufferedInputStream(socket.getInputStream());
                phoneOut = new BufferedOutputStream(socket.getOutputStream());
            } catch(Exception e)
            {
            }
            busy = true;
            start();
        }

        return error;
    }

    public void close()
    {
//            interrupt();
        if(busy)
        {
            try{
                sendFIN = false;
                socket.close();
                join();
            } catch(Exception e)
            {
            }
            busy = false;
        }
    }

    public String getTitle()
    {
        return src.toString() + 
            ":" + srcPort + 
            " -> " + dst.toString() + 
            ":" + dstPort;
    }


// forward packets from phone to client
    public void run()
    {
// maximum payload per packet
//        byte[] buffer = new byte[Server.MTU - Server.IP_HEADER_SIZE - Server.TCP_HEADER_SIZE];
        byte[] buffer = new byte[Server.MAX_PAYLOAD * 64];
// output packet
        byte[] packet = new byte[Server.MTU];
        while(true)
        {
            int bytes_read = 0;
            try{
                bytes_read = phoneIn.read(buffer, 0, buffer.length);
            } catch(Exception e)
            {
            }

//             Log.i("TCPThread", "run #" + threadNumber + 
//                 " got " + bytes_read + " from phone");
            if(bytes_read <= 0) break;

            for(int offset = 0; offset < bytes_read; offset += Server.MAX_PAYLOAD)
            {
// forward to client
                int fragment = Server.MAX_PAYLOAD;
                if(offset + fragment > bytes_read)
                    fragment = bytes_read - offset;
                int total_size = Server.IP_HEADER_SIZE + Server.TCP_HEADER_SIZE + fragment;
                packet[0] = 0x45; // IPv4
                packet[1] = 0;
                Math2.write_uint16be(packet, 2, total_size);
                synchronized(this)
                {
                    Math2.write_uint16be(packet, 4, id); // ID
                    id += 1;
                }
                Math2.write_uint16be(packet, 6, 0x4000); // flags, offset
                packet[8] = 64; // TTL
                packet[9] = Server.PROTO_TCP;
                Math2.write_address(packet, 12, dst);
                Math2.write_address(packet, 16, src);

    // TCP
                Math2.write_uint16be(packet, 20, dstPort);
                Math2.write_uint16be(packet, 22, srcPort);
                Math2.write_uint32be(packet, 24, getAbsMySequence());
                Math2.write_uint32be(packet, 28, getAbsClientSequence());
                mySequence += fragment; 
// PSH ACK
//              if(total_size < Server.MTU)
                    Math2.write_uint16be(packet, 32, Server.encodeTcpFlags(Server.TCP_HEADER_SIZE, 0x0018));
//              else
// ACK
//                  Math2.write_uint16be(packet, 32, Server.encodeTcpFlags(Server.TCP_HEADER_SIZE, 0x0010));

                Math2.write_uint16be(packet, 34, myWindowSize / windowScale); // window size
                Math2.write_uint16be(packet, 38, 0x0000); // urgent pointer
                packet[40] = 0x01;
                packet[41] = 0x01;
    // no timestamps
                packet[42] = 0x01;
                packet[43] = 0x01;
    //                packet[42] = 0x08; // timestamp option
    //                packet[43] = 0x0a; // timestamp length
    //                Math2.write_uint32be(packet, 44, 0x0); // timestamp
    //                Math2.write_uint32be(packet, 48, 0x0); // timestamp
                System.arraycopy(buffer, offset, packet, Server.IP_HEADER_SIZE + Server.TCP_HEADER_SIZE, fragment); // the payload


                Server.tcp_chksum(packet, total_size);
                server.writeClient(packet, 0, total_size);
            }
        }

        if(sendFIN)
        {
// closed by the phone.  Send the FIN ACK
//                Log.i("TCPThread", "run: sending FIN");

// no timestamps
            int total_size = Server.IP_HEADER_SIZE + Server.TCP_HEADER_SIZE;
            packet[0] = 0x45; // IPv4
            packet[1] = 0;
            Math2.write_uint16be(packet, 2, total_size);
            synchronized(this)
            {
                Math2.write_uint16be(packet, 4, id); // ID
                id += 1;
            }
            Math2.write_uint16be(packet, 6, 0x4000); // flags, offset
            packet[8] = 64; // TTL
            packet[9] = Server.PROTO_TCP;
            Math2.write_address(packet, 12, dst);
            Math2.write_address(packet, 16, src);

// TCP
            Math2.write_uint16be(packet, 20, dstPort);
            Math2.write_uint16be(packet, 22, srcPort);
            Math2.write_uint32be(packet, 24, getAbsMySequence());
            Math2.write_uint32be(packet, 28, getAbsClientSequence());
// data offset + flags
            Math2.write_uint16be(packet, 32, Server.encodeTcpFlags(Server.TCP_HEADER_SIZE, 0x0011));
            Math2.write_uint16be(packet, 34, myWindowSize / windowScale); // window size
            Math2.write_uint16be(packet, 38, 0x0000); // urgent pointer
// options
            packet[40] = 0x01;
            packet[41] = 0x01;
// no timestamps
            packet[42] = 0x01;
            packet[43] = 0x01;

            Server.tcp_chksum(packet, total_size);
            server.writeClient(packet, 0, total_size);

            try{
                socket.close();
            } catch(Exception e)
            {
                Log.i("TCPThread", "run " + getTitle() + 
                    " " + e.toString());
            }
        }



        busy = false;
    }
}





