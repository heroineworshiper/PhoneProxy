/*
 * PhoneProxy
 * Copyright (C) 2025 Adam Williams <broadcast at earthling dot net>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 */

#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/tcp.h>
#include <netdb.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

// client program for phone proxy
// gcc -O2 -o phoneproxy phoneproxy.c -lpthread
// Usage:
// ./phoneproxy [phone address] [virtual address]

// route add default gw [virtual address]


#define BUFSIZE 4096
#define TEXTLEN 1024
#define TAP_PATH "/dev/net/tun"
#define DEVICE_NAME "phone0"
#define MTU 1500
#define PORT 8100
#define PHONE_ADDRESS "10.0.5.149"
#define VIRTUAL_ADDRESS "10.12.0.1"

char *device_name = 0;
char server[TEXTLEN];
char local[TEXTLEN];
char default_gw[TEXTLEN] = { 0 };
int tun_fd = -1;
int socket_fd = -1;
pthread_mutex_t tun_lock;
int window_size = 8192;
int window_scale = 1;
int got_signal = 0;

typedef struct
{
    uint8_t data[BUFSIZE];
    int packet_offset;
    int packet_size;
} packet_t;

pthread_mutex_t fifo_lock;
sem_t fifo_read_sem;
sem_t fifo_write_sem;
#define FIFO_MAX 0x8000000
uint8_t fifo_buf[FIFO_MAX];
int fifo_offset1 = 0;
int fifo_offset2 = 0;
int fifo_used = 0;

void quit();

void align_packets(packet_t *packet, 
    char *src, 
    int bytes_read, 
    void (*send_it)(packet_t*))
{
    int i;
    for(i = 0; i < bytes_read; i++)
    {
        if(packet->packet_offset == 0)
        {
            if(src[i] == 0x45)
                packet->data[packet->packet_offset++] = src[i];
        }
        else
        if(packet->packet_offset < 4)
        {
             packet->data[packet->packet_offset++] = src[i];
             if(packet->packet_offset >= 4)
                packet->packet_size = (packet->data[2] << 8) | packet->data[3];
        }
        else
        {
            packet->data[packet->packet_offset++] = src[i];
            if(packet->packet_offset >= packet->packet_size)
            {
                send_it(packet);
                packet->packet_offset = 0;
                packet->packet_size = 0;
            }
        }
    }
}


#define IP_HEADER_SIZE 20
#define TCP_HEADER_SIZE 24
#define PROTO_TCP 0x06
int decodeTcpSize(uint32_t flags)
{
    return ((flags >> 12) & 0xf) * 4;
}

uint32_t encodeTcpFlags(int size, uint32_t flags)
{
    return ((size / 4) << 12) | flags;
}

// full chksum
uint16_t chksum(uint8_t *data, int offset, int size)
{
    uint16_t sum = 0;
	int ptr = offset;
	int end = offset + size - 1;
	uint16_t t;

	while(ptr < end)
	{
		t = (data[ptr] << 8) | data[ptr + 1];
		sum += t;
        if(sum < t) sum++; // add 1 if carry
		ptr += 2;
	}

	if(ptr == end)
	{
		t = data[ptr] << 8;
		sum += t;
        if(sum < t) sum++; // add 1 if carry
	}

    if(sum == 0) sum = 0xffff;
    sum = ~sum;
	return sum;
}

// partial chksum
uint16_t chksum2(uint16_t sum, uint8_t *data, int offset, int size)
{
	int ptr = offset;
	int end = offset + size - 1;
	uint16_t t;

	while(ptr < end)
	{
		t = (data[ptr] << 8) | data[ptr + 1];
		sum += t;
        if(sum < t) sum++; // add 1 if carry
		ptr += 2;
	}

	if(ptr == end)
	{
		t = data[ptr] << 8;
		sum += t;
        if(sum < t) sum++; // add 1 if carry
	}

	return sum;
}

// stuff the chksums
void tcp_chksum(uint8_t *packet, int total_size)
{
// header chksum
// reset header chksum
    packet[10] = 0;
    packet[11] = 0;
    uint32_t sum = chksum(packet, 0, IP_HEADER_SIZE);
    packet[10] = (sum >> 8) & 0xff;
    packet[11] = sum & 0xff;

    uint8_t pseudo_hdr[12];
    int pseudo_size = total_size - IP_HEADER_SIZE;
    memcpy(&pseudo_hdr[0], &packet[12], 8); // addresses
    pseudo_hdr[8] = 0;
    pseudo_hdr[9] = PROTO_TCP;
    pseudo_hdr[10] = (pseudo_size >> 8) & 0xff;
    pseudo_hdr[11] = pseudo_size & 0xff;

// TCP chksum
// reset TCP chksum
    packet[36] = 0;
    packet[37] = 0;
    sum = chksum2(0, pseudo_hdr, 0, sizeof(pseudo_hdr));
    sum = chksum2(sum, packet, IP_HEADER_SIZE, pseudo_size);
    if(sum == 0) sum = 0xffff;
    sum = ~sum;
    packet[36] = (sum >> 8) & 0xff;
    packet[37] = sum & 0xff;
}

void phone_writer(void *ptr)
{
    while(1)
    {
// wait for new data
        sem_wait(&fifo_read_sem);
        
        pthread_mutex_lock(&fifo_lock);
        while(fifo_used > 0)
        {
            int fragment = fifo_used;
            if(fifo_offset2 + fragment > FIFO_MAX)
                fragment = FIFO_MAX - fifo_offset2;

            pthread_mutex_unlock(&fifo_lock);
            int bytes_written = write(socket_fd, &fifo_buf[fifo_offset2], fragment);
            if(bytes_written <= 0)
            {
                printf("phone_writer %d: phone disconnected. bytes_written=%d\n",
                    __LINE__,
                    bytes_written);
            }
            pthread_mutex_lock(&fifo_lock);

            fifo_offset2 += fragment;
            fifo_used -= fragment;
            if(fifo_offset2 >= FIFO_MAX)
                fifo_offset2 = 0;
        }
        pthread_mutex_unlock(&fifo_lock);

// allow new data
        sem_post(&fifo_write_sem);
    }
}

void write_fifo(uint8_t *buffer, int size)
{
// wait for enough space
    while(fifo_used + size > FIFO_MAX)
    {
        printf("write_fifo %d: fifo full\n", __LINE__);
        sem_wait(&fifo_write_sem);
    }

    int offset = 0;
    while(offset < size)
    {
        int fragment = size - offset;
        if(fifo_offset1 + fragment > FIFO_MAX)
            fragment = FIFO_MAX - fifo_offset1;

        memcpy(&fifo_buf[fifo_offset1], &buffer[offset], fragment);

        fifo_offset1 += fragment;
        offset += fragment;
        if(fifo_offset1 >= FIFO_MAX)
            fifo_offset1 = 0;
    }

    pthread_mutex_lock(&fifo_lock);
    fifo_used += size;
    pthread_mutex_unlock(&fifo_lock);

//    printf("write_fifo %d: size=%d fifo_used=%d\n", __LINE__, size, fifo_used);
// allow reads
    sem_post(&fifo_read_sem);
}

void write_phone(packet_t *packet_)
{
// Discard ACKS from client without payloads.
    uint8_t *packet = packet_->data;
    int total_size = packet_->packet_size;
    int payload_size = 0;
    if(total_size >= IP_HEADER_SIZE + TCP_HEADER_SIZE &&
        packet[8] > 1 && // TTL
        packet[9] == PROTO_TCP)
    {
        uint32_t flags = (packet[32] << 8) | packet[33];
        if((flags & 0x0010) == 0x0010 &&
            (flags & 0x0001) == 0)
        {
// ACK not FIN from client
            int tcp_header_size = decodeTcpSize(flags);
            int payload_offset = tcp_header_size + IP_HEADER_SIZE;
            payload_size = total_size - payload_offset;
// drop if no payload
            if(payload_size <= 0) return;
        }
    }


    write_fifo(packet, total_size);
//    int _ = write(socket_fd, packet, total_size);

// Synthesize ACK for payload from client
    if(payload_size > 0)
    {
        int return_size = IP_HEADER_SIZE + TCP_HEADER_SIZE;
        uint8_t src[4];
        uint8_t dst[4];

        packet[2] = (return_size >> 8) & 0xff;
        packet[3] = return_size & 0xff;
        memcpy(src, &packet[12], 4);
        memcpy(dst, &packet[16], 4);
        uint8_t srcPort[2];
        uint8_t dstPort[2];
        memcpy(srcPort, &packet[20], 2);
        memcpy(dstPort, &packet[22], 2);
        uint32_t clientSequence = (packet[24] << 24) |
            (packet[25] << 16) |
            (packet[26] << 8) |
            (packet[27]);
        uint32_t mySequence = (packet[28] << 24) |
            (packet[29] << 16) |
            (packet[30] << 8) |
            (packet[31]);
        clientSequence += payload_size;

        memcpy(&packet[12], dst, 4);
        memcpy(&packet[16], src, 4);
        memcpy(&packet[20], dstPort, 2);
        memcpy(&packet[22], srcPort, 2);
        packet[24] = (mySequence >> 24) & 0xff;
        packet[25] = (mySequence >> 16) & 0xff;
        packet[26] = (mySequence >> 8) & 0xff;
        packet[27] = mySequence & 0xff;
        packet[28] = (clientSequence >> 24) & 0xff;
        packet[29] = (clientSequence >> 16) & 0xff;
        packet[30] = (clientSequence >> 8) & 0xff;
        packet[31] = clientSequence & 0xff;
        
        uint32_t flags = encodeTcpFlags(TCP_HEADER_SIZE, 0x0010);
        packet[32] = (flags >> 8) & 0xff;
        packet[33] = flags & 0xff;
        int scaled_window = window_size / window_scale;
        packet[34] = (scaled_window >> 8) & 0xff;
        packet[35] = (scaled_window & 0xff);
// no timestamps.  Get a RST if we send timestamps
        packet[40] = 0x01;
        packet[41] = 0x01;
// no timestamps.  Get a RST if we send timestamps
        packet[42] = 0x01;
        packet[43] = 0x01;
        tcp_chksum(packet, return_size);

        pthread_mutex_lock(&tun_lock);
        int _ = write(tun_fd, packet, return_size);
        pthread_mutex_unlock(&tun_lock);
    }

//     int min_size = 1024;
//     static uint8_t packet_padded[4096];
//     int total_size = packet->packet_size;
//     memcpy(packet_padded, packet->data, packet->packet_size);
//     if(packet->packet_size < min_size)
//     {
//         total_size = min_size;
//         memset(packet_padded + packet->packet_size, 
//             0xff, 
//             min_size - packet->packet_size);
//     }
// 
//     int _ = write(socket_fd, packet_padded, total_size);
}

// read packets from Linux
void tun_reader(void *ptr)
{
    char buffer[BUFSIZE];
    packet_t packet;
    bzero(&packet, sizeof(packet));

    while(1)
    {
        int bytes_read = read(tun_fd, buffer, BUFSIZE);
        if(bytes_read < 0)
        {
            printf("tun disconnected. bytes_read=%d", bytes_read);
            quit();
            exit(1);
        }

        align_packets(&packet, 
            buffer,
            bytes_read,
            write_phone);
//printf("tun_reader %d: got %d bytes from tun\n", __LINE__, bytes_read);
    }
}


// from python-pytun-2.4.1/pytun.c
static int if_ioctl(int cmd, struct ifreq* req)
{
    int ret;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0);
    ret = ioctl(sock, cmd, req);
    close(sock);
    if(ret < 0)
    {
        printf("if_ioctl: ret=%d\n", ret);
    }

    return ret;
}

void write_tun(packet_t *packet_)
{
// extract phone window parameters from the SYN ACKs
    uint8_t *packet = packet_->data;
    int total_size = packet_->packet_size;
    if(total_size >= IP_HEADER_SIZE + TCP_HEADER_SIZE &&
        packet[8] > 1 && // TTL
        packet[9] == PROTO_TCP)
    {
        uint32_t flags = (packet[32] << 8) | packet[33];
// got SYN ACK
        if((flags & 0x0fff) == 0x0012)
        {
// get the options
            int offset = 40;
            while(offset < total_size)
            {
                int kind = packet[offset++];
                int size = 0;
                switch(kind)
                {
                    case 2: // maximum segment size
                        size = packet[offset++];
                        offset += size - 2;
                        break;
                    case 4: // SACK permitted
                        size = packet[offset++];
                        offset += size - 2;
                        break;
                    case 3: // window scaler
                        size = packet[offset++];
                        window_scale = (1 << packet[offset++]);
if(window_scale != 128)
printf("write_tun %d: window_scale=%d\n", __LINE__, window_scale);
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
            window_size = 1;
            while(window_size < 0x80000 &&
                window_size / window_scale < 65535)
                window_size += window_scale;
        }
    }

    pthread_mutex_lock(&tun_lock);
    int _ = write(tun_fd, packet, total_size);
    pthread_mutex_unlock(&tun_lock);
}

void quit()
{
    char string[TEXTLEN];
    if(default_gw[0] != 0 && !got_signal)
    {
        got_signal = 1;
        printf("Restoring default gateway:\n");
        sprintf(string, "route del default");
        printf("%s\n", string);
        int _ = system(string);
        sprintf(string, "route add default gw %s", default_gw);
        printf("%s\n", string);
        _ = system(string);
    }
    exit(0);
}

int main(int argc, char *argv[])
{
    int i;
    char string[TEXTLEN];
    strcpy(server, PHONE_ADDRESS);
    strcpy(local, VIRTUAL_ADDRESS);
    
    
    if(argc >= 2 && !strcmp(argv[1], "-h"))
    {
        printf("Usage: %s <phone address> <virtual gateway address>\n", argv[0]);
        printf("Example: %s %s %s\n", argv[0], PHONE_ADDRESS, VIRTUAL_ADDRESS);
        printf("Default phone: %s\n", PHONE_ADDRESS);
        printf("Default virtual gateway: %s\n", VIRTUAL_ADDRESS);
        exit(0);
    }

    if(argc >= 2) strcpy(server, argv[1]);
    if(argc >= 3) strcpy(local, argv[2]);

// back up the current gateway
    FILE *fd = fopen("/proc/net/route", "r");
    while(fgets(string, TEXTLEN, fd)) 
    {
        uint32_t destination;
        uint32_t gateway;
        uint32_t netmask;
        int n = sscanf(string, 
            "%*s %x %x %*s %*s %*s %*s %x",
            &destination,
            &gateway,
            &netmask);
        if(n < 3) continue;

//        printf("%s%08x %08x %08x\n", string, destination, gateway, netmask);
        if(destination == 0 && netmask == 0)
        {
            sprintf(default_gw, 
                "%d.%d.%d.%d", 
                (gateway & 0xff),
                (gateway >> 8) & 0xff,
                (gateway >> 16) & 0xff,
                (gateway >> 24) & 0xff);

            printf("Backing up default gateway: %s\n", default_gw);
        }
    }
    fclose(fd);

    signal(SIGINT, quit);
    signal(SIGSEGV, quit);

	pthread_mutexattr_t attr2;
	pthread_mutexattr_init(&attr2);
    pthread_mutex_init(&tun_lock, &attr2);
    pthread_mutex_init(&fifo_lock, &attr2);
    sem_init(&fifo_read_sem, 0, 0);
    sem_init(&fifo_write_sem, 0, 0);

    printf("Phone address: %s\nGateway address: %s\n",
        server,
        local);

// from python-pytun-2.4.1/pytun.c
// initialize the virtual ethernet device
    tun_fd = open(TAP_PATH, O_RDWR|O_CLOEXEC);
    if(tun_fd < 0)
    {
        printf("Failed to open TUN device. %s", strerror(errno));
        return 1;
    }
    

    struct ifreq req;
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, DEVICE_NAME);
// actually have to create a TUN device instead of a TAP device 
// for user space networking
    req.ifr_flags = IFF_TUN | IFF_NO_PI;
    int result = ioctl(tun_fd, TUNSETIFF, &req);
    if (result < 0)
    {
        printf("Error creating %s device: %s", DEVICE_NAME, strerror(errno));
        close(tun_fd);
        tun_fd = -1;
        return 1;
    }

    if (ioctl(tun_fd, TUNSETPERSIST, 1) < 0)
    {
        printf("TUNSETPERSIST: %s", strerror(errno));
    }

    device_name = strdup(req.ifr_name);
//    printf("init_tap %d: result=%d ifr_name=%s\n", __LINE__, result, req.ifr_name);

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, device_name);
    req.ifr_mtu = MTU;
    if(if_ioctl(SIOCSIFMTU, &req) < 0)
    {
        printf("failed to set MTU");
    }



// connect to the phone
	struct sockaddr_in addr;
	struct hostent *hostinfo;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	hostinfo = gethostbyname(server);
	if(hostinfo == NULL)
	{
		perror("gethostbyname");
		return 1;
	}
	addr.sin_addr = *(struct in_addr *)hostinfo->h_addr;

	if((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket");
		return 1;
	}

    printf("main %d: connecting to phone %s:%d\n", __LINE__, server, PORT);
	if(connect(socket_fd, 
		(struct sockaddr*)&addr, 
		sizeof(addr)) < 0)
	{
		perror("connect");
		return 1;
	}

    printf("main %d: connected to phone\n", __LINE__);
    int flag = 1;
    setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));

// bring it up
    sprintf(string, 
        "ifconfig %s %s netmask 255.255.255.255 up\n", 
        DEVICE_NAME,
        local);
    printf("%s", string);
    int _ = system(string);
    sprintf(string, "route del default\n");
    printf("%s", string);
    _ = system(string);
    sprintf(string, "route add default gw %s\n", local);
    printf("%s", string);
    _ = system(string);

// read from tunnel & write to the phone
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_t tid;
	pthread_create(&tid, 
		&attr, 
		(void*)phone_writer, 
		0);
	pthread_create(&tid, 
		&attr, 
		(void*)tun_reader, 
		0);

// read from the phone & write to tunnel
    char buffer[BUFSIZE];
// reconstructed packet
    packet_t packet;
    bzero(&packet, sizeof(packet));
    while(1)
    {
// forward data straight to tunnel
        int bytes_read = read(socket_fd, buffer, BUFSIZE);
        if(bytes_read <= 0)
        {
            printf("main %d: phone disconnected. bytes_read=%d\n", 
                __LINE__, bytes_read);
            quit();
            exit(1);
        }

// packets from the phone are not aligned but
// we have to align the tunnel writes
        align_packets(&packet, 
            buffer, 
            bytes_read, 
            write_tun);
//printf("main %d: got %d bytes from phone\n", __LINE__, bytes_read);
    }
}




