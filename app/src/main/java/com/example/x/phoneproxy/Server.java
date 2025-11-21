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


// entry point into the proxy server

package com.example.x.phoneproxy;

import android.util.Log;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;


public class Server extends Thread
{
    public static final int TOTAL_CONNECTIONS = 32;
    public static final int TOTAL_REQUESTS = 256;
    public static final int TOTAL_TCP = 256;
    public ServerThread server_threads[] = new ServerThread[TOTAL_CONNECTIONS];
    public static Server server;

    public static final int PROTO_ICMP = 0x01;
    public static final int PROTO_UDP = 0x11;
    public static final int PROTO_TCP = 0x06;
    public static final int IP_HEADER_SIZE = 20;
// TCP header without timestamps
    public static final int TCP_HEADER_SIZE = 24;
    public static final int BUFSIZE = 65536;
    public static final int MTU = 1500;
    public static final int MAX_PAYLOAD = MTU - IP_HEADER_SIZE - TCP_HEADER_SIZE;

    public void run()
    {

        ServerSocket socket = null;
        try {
            socket = new ServerSocket(Stuff.PORT);
        } catch (IOException e) {
            Log.v("Server", "run: Could not start server: " + e);
        }

        Log.v("Server", "run: started server on port " + Stuff.PORT);


        // request handler loop
        while (true) {
            Socket connection = null;
            try {
                // wait for request
                connection = socket.accept();
                Log.v("Server", "run: got connection");
                if(connection != null) startConnection(connection);

            } catch (IOException e)
            {
                Log.v("Server", "run: " + e);
            }
        }
    }


    void startConnection(Socket connection)
    {
        ServerThread thread = null;
        try {
            connection.setTcpNoDelay(true);
        } catch (SocketException e) {
            e.printStackTrace();
        }
        synchronized(this)
        {
            for(int i = 0; i < TOTAL_CONNECTIONS; i++)
            {
                if(server_threads[i] == null)
                    server_threads[i] = new ServerThread();

                if(!server_threads[i].busy)
                {
                    thread = server_threads[i];
                    server_threads[i].startConnection(connection);
                    break;
                }
            }
        }

        if(thread == null)
        {
            Log.v("Server", "startConnection: out of threads");
            return;
        }



    }


// stuff the chksums
    static public void tcp_chksum(byte[] packet, int total_size)
    {
// header chksum
// reset header chksum
        packet[10] = 0;
        packet[11] = 0;
        int sum = Math2.chksum(packet, 0, IP_HEADER_SIZE);
        Math2.write_uint16be(packet, 10, sum);

        byte[] pseudo_hdr = new byte[12];
        System.arraycopy(packet, 12, pseudo_hdr, 0, 8); // addresses
        pseudo_hdr[8] = 0;
        pseudo_hdr[9] = PROTO_TCP;
        Math2.write_uint16be(pseudo_hdr, 10, total_size - IP_HEADER_SIZE);

// TCP chksum
// reset TCP chksum
        packet[36] = 0;
        packet[37] = 0;
        sum = Math2.chksum2(0, pseudo_hdr, 0, pseudo_hdr.length);
        sum = Math2.chksum2(sum, packet, IP_HEADER_SIZE, total_size - IP_HEADER_SIZE);
        if(sum == 0) sum = 0xffff;
        sum = ~sum;
        Math2.write_uint16be(packet, 36, sum);
    }

    static public int decodeTcpSize(int flags)
    {
        return ((flags >> 12) & 0xf) * 4;
    }

    static public int encodeTcpFlags(int size, int flags)
    {
        return ((size / 4) << 12) | flags;
    }


}
