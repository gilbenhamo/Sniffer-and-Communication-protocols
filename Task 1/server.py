import socket

localIP     = "127.0.0.1"
localPort   = 12321
bufferSize  = 1024
 
# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and ip
UDPServerSocket.bind((localIP, localPort))

print("UDP server up and listening")


# Listen for incoming datagrams
while(True):
    message, address = UDPServerSocket.recvfrom(bufferSize)
    message = message.decode('utf-8').split(' ',1)
    clientMsg = f"Server got message {message[0]} from {address[0]}:\n{message[1]}"
    #clientIP  = "Client IP Address:{}".format(address)
    
    print(clientMsg)

    # Sending a reply to client
    msgFromServer = "Server recived packet " + message[0]
    bytesToSend = str.encode(msgFromServer)
    UDPServerSocket.sendto(bytesToSend, address)