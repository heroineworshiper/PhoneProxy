package com.example.x.phoneproxy;

import android.util.Log;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class Math2 {

    static public int read_uint16be(byte[] data, int offset)
	{
    	return ((int)(data[offset + 1] & 0xff)) | 
            ((((int)data[offset]) << 8) & 0xff00);
	}

	static public int read_int32be(byte[] data, int offset)
	{
		return (data[offset + 3] & 0xff) | 
			((data[offset + 2] & 0xff) << 8) | 
			((data[offset + 1] & 0xff) << 16) | 
			((data[offset + 0]) << 24);
	}

	static public long read_uint32be(byte[] data, int offset)
	{
		long result = (((long)data[offset + 3]) & 0xff) | 
			(((long)data[offset + 2] & 0xff) << 8) | 
			(((long)data[offset + 1] & 0xff) << 16) | 
			(((long)data[offset + 0]) << 24);
        result &= 0xffffffffL;
        return result;
	}

    static public InetAddress read_address(byte[] data, int offset)
    {
        byte[] data2 = new byte[4];
		data2[0] = data[offset];
		data2[1] = data[offset + 1];
		data2[2] = data[offset + 2];
		data2[3] = data[offset + 3];

        InetAddress result = null;
		try {
			result = InetAddress.getByAddress(data2);
		} catch (UnknownHostException e) {
		}
		return result;
	}

	static public int write_uint16be(byte[] data, int offset, int value)
	{
		data[offset++] = (byte)((value >> 8) & 0xff);
		data[offset++] = (byte)(value & 0xff);
		return offset;
	}

	static public int write_uint32be(byte[] data, int offset, int value)
	{
		data[offset++] = (byte)((value >> 24) & 0xff);
		data[offset++] = (byte)((value >> 16) & 0xff);
		data[offset++] = (byte)((value >> 8) & 0xff);
		data[offset++] = (byte)(value & 0xff);
		return offset;
	}

    static public void write_address(byte[] data, int offset, InetAddress addr)
    {
        data[offset] = addr.getAddress()[0];
        data[offset + 1] = addr.getAddress()[1];
        data[offset + 2] = addr.getAddress()[2];
        data[offset + 3] = addr.getAddress()[3];
    }


// full chksum
    static int chksum(byte[] data, int offset, int size)
    {
    	int sum = 0;
	    int ptr = offset;
	    int end = offset + size - 1;
	    int t;

	    while(ptr < end)
	    {
		    t = read_uint16be(data, ptr);
		    sum += t;
            sum &= 0xffff;
            if(sum < t) sum++; // add 1 if carry
		    ptr += 2;
	    }

	    if(ptr == end)
	    {
		    t = (((int)data[ptr]) << 8) & 0xff00;
		    sum += t;
            sum &= 0xffff;
            if(sum < t) sum++; // add 1 if carry
	    }

        if(sum == 0) sum = 0xffff;
        sum = ~sum;
	    return sum;
    }

// partial chksum
    static int chksum2(int sum, byte[] data, int offset, int size)
    {
	    int ptr = offset;
	    int end = offset + size - 1;
	    int t;

	    while(ptr < end)
	    {
		    t = read_uint16be(data, ptr);
		    sum += t;
            sum &= 0xffff;
            if(sum < t) sum++; // add 1 if carry
		    ptr += 2;
	    }

	    if(ptr == end)
	    {
		    t = (((int)data[ptr]) << 8) & 0xff00;
		    sum += t;
            sum &= 0xffff;
            if(sum < t) sum++; // add 1 if carry
	    }

	    return sum;
    }
}

