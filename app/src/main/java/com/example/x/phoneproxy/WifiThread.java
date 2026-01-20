/*
 * PhoneProxy
 * Copyright (C) 2026 Adam Williams <broadcast at earthling dot net>
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

// since the phone randomly disconnects if it can't phone home over wifi, this
// monitors the access point & tries to reconnect

// the gopro app does this properly, but it might be using just the right 
// API level

package com.example.x.phoneproxy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Log;

import java.util.List;

public class WifiThread extends Thread
{
    Context context;
    static WifiThread instance;

    public WifiThread(Context context)
    {
        this.context = context;
        start();
    }

    public void run()
    {
        ConnectivityManager cm = (ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        WifiManager wm = (WifiManager)context.getSystemService(Context.WIFI_SERVICE);

        while(true)
        {
            try { Thread.sleep(1000); } catch(Exception e) {}
            
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP)
            {
                Network[] networks = cm.getAllNetworks();
                if(networks != null)
                {
//                    Log.i("WifiThread", "networks=" + networks.length);
                    boolean gotIt = false;
                    for(int i = 0; i < networks.length; i++)
                    {
                        NetworkCapabilities caps = cm.getNetworkCapabilities(networks[i]);
//                        Log.i("WifiThread", "i=" + i +
//                            " name=" + caps.toString());
//                            " wifi=" + caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI));

// can't get the SSID but can get if it's wifi
                        if(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
                        {
                            gotIt = true;
                            break;
                        }
                    }

                    if(!gotIt)
                    {
                        Log.i("WifiThread", "reconnecting");
                        List<WifiConfiguration> configs  = wm.getConfiguredNetworks();
                        for(int i = 0; i < configs.size(); i++) {
                            WifiConfiguration config = configs.get(i);
                            Log.i("WifiThread", "got " + config.SSID);
                            if(config.SSID != null && 
                                config.SSID.equals("\"" + Server.WANT_SSID + "\"")) 
                            {
                                wm.enableNetwork(config.networkId, true);
                                Log.i("WifiThread", "got SSID");
                                break;
                            }
                        }
                        wm.reconnect();
                    }
                }
            }

//            Log.i("WifiThread", "SSID=" + lastKnownSsid + " BSSID=" + lastKnownBssid);
        }
        
        
        
    }
}


