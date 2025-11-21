#!/usr/bin/python3

# TCP test server

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
            print("server received: %d bytes %d total" % (len(data), total))
            for i in range(len(data)):
                if data[i] != (counter & 0xff):
                    error = True
                    print("Got error at %d" % i)
                    print("%d: %02x %02x %02x %02x" % (i - 4, data[i - 4], data[i - 3], data[i - 2], data[i - 1]))
                    print("%d: %02x %02x %02x %02x" % (i, data[i], data[i + 1], data[i + 2], data[i + 3]))
                    break;
                counter += 1;
        else:
            print("peer closed");
            error = True




# Create a TCP/IP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to address and port
#host = '10.0.10.29' # grid22 vethAVEWXN
host = '10.12.0.2' # piano
port = 1234

message = bytearray((i % 256) for i in range(1024))

server_socket.bind((host, port))

# Listen for incoming connections (max 5 queued)
server_socket.listen(5)
print(f"Server listening on {host}:{port}")

# Accept a client connection
client_socket, client_address = server_socket.accept()
print(f"Connection from {client_address}")

thread = threading.Thread(target=reader)
thread.start()

time.sleep(1)

# send data
while not error:
    client_socket.sendall(message)
    time.sleep(1)






# Echo back
#        message = "Hello, Client!"
#        client_socket.sendall(message.encode('utf-8'))

#        client_socket.sendall(data)

# Close the connection.  Don't close on client.  
# Causes a TIMED_WAIT on the server
#        client_socket.close()
#        exit()

#    else:

#        print("Client closed");
#        exit()




