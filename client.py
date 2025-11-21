#!/usr/bin/python3

# TCP test client.

import threading
import socket
import time

error = False


# Receive data from the client
def reader():
    global error
    counter = 0
    total = 0
    while not error:
        data = client_socket.recv(65536)
        if data:
            #print(f"Received: {data.decode('utf-8')}")
            total += len(data)
            print("client received: %d bytes %d total" % (len(data), total))
            for i in range(len(data)):
                if data[i] != (counter & 0xff):
                    error = True
                    print("Got error at %d" % i)
                    if i >= 4:
                        print("%d: %02x %02x %02x %02x" % (i - 4, data[i - 4], data[i - 3], data[i - 2], data[i - 1]))
                    if i <= len(data) - 4:
                        print("%d: %02x %02x %02x %02x" % (i, data[i], data[i + 1], data[i + 2], data[i + 3]))
                    break;
                counter += 1;
        else:
            print("peer closed");
            error = True

# Create a TCP/IP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Server details
#host = '10.0.10.29' # grid22 vethAVEWXN
host = '10.12.0.2' # piano
port = 1234

# Connect to the server
client_socket.connect((host, port))


# Send text
#message = "Hello, Server!"
#client_socket.sendall(message.encode('utf-8'))

# send data
message = bytearray((i % 256) for i in range(1024))

thread = threading.Thread(target=reader)
thread.start()

time.sleep(1)

while not error:
    client_socket.sendall(message)
    time.sleep(1)

# Close the connection.  Don't close on server.
#client_socket.close()
#exit()


#    else:
#        print("Server closed");
#        exit()

# Close the connection.  Don't close on server.
#    client_socket.close()
#    exit()



