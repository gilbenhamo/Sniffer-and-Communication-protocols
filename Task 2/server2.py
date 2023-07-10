import socket
from socket import timeout as TimeoutException

localIP     = "127.0.0.1"
localPort   = 12321
bufferSize  = 1024

RETRANSMISSION_MSG = 'Error - retransmission is nedded'
WARNING_MSG = 'WARNING - High probability of an Adversary attack'
HANDSHAKE_CREATED_MSG = 'Handshake created successfully'
FIN_MSG = 'Connection end'
MAX_PACKET_LOST_PER_SN = 5
MAX_OVERHEAD_PACKETLOST = 2
PACKET_LOST_TIMEOUT = 5
MIN_RETRANSMISSIONS = 8

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
# Bind to address and ip
UDPServerSocket.bind((localIP, localPort))

def sendMsg(msg,address):
    bytesToSend = str.encode(msg)
    UDPServerSocket.sendto(bytesToSend, address)

def askForRetransmition():
    global KeepAliveflag,counter,server_e,retransmission_counter
    retransmission_counter+=1
    # counter = 0
    KeepAliveflag = True
    server_e = server_e_bu
    sendMsg(RETRANSMISSION_MSG,address)

def updateDroppedList():
    #updated dropped packages list - keep history of which packages dropped
    for i in range(0,d):
        if not arrived_packages_flags[i]:
            drop_packages_counter[i]+=1

def checkForExistsAttack():
    '''
        conds:
        1.	If at least 80% of the messages (0.8*d) didn’t arrive at least 2 times .
        2.	If a specific packet does not arrive at least 5 times.
        3.	If all d packets were retransmitted at least max(8,0.5*d) times.
    '''
    global overhead_packetlost_counter
    if max(drop_packages_counter) >= MAX_PACKET_LOST_PER_SN or retransmission_counter >= MAX_RETRANSMISSIONS:
        return True
    if arrived_packages_flags.count(False)>=MAX_PACKET_LOST_PER_TRANSMISSION:
        overhead_packetlost_counter+=1
        if overhead_packetlost_counter >= MAX_OVERHEAD_PACKETLOST:
            return True
    return False

print("UDP server up and listening on port:",localPort)

while True:
    # get e and d from the client - Handshake
    message, address = UDPServerSocket.recvfrom(bufferSize)
    message = message.decode('utf-8')
    d,server_e = message.split(" ",1)
    server_e_bu = server_e
    print("client e is " + server_e + "\nd is "+d)
    try:
        d = int(d)
    except ValueError:
        continue
    sendMsg(HANDSHAKE_CREATED_MSG,address)

    drop_packages_counter = [0]*d             #list that indicate which packges droped while the connection
    retransmission_counter = 0
    overhead_packetlost_counter = 0

    #Define warning values
    MAX_RETRANSMISSIONS = max(d*0.5,MIN_RETRANSMISSIONS)
    MAX_PACKET_LOST_PER_TRANSMISSION = 0.8*d

    # Listen for incoming datagrams
    KeepAliveflag = True
    # counter = 0
    UDPServerSocket.settimeout(PACKET_LOST_TIMEOUT)
    while KeepAliveflag:
        arrived_packages_flags = [False]*d
        KeepAliveflag = False
        for i in range(0,d):
            try:
                #got message from client
                message, address = UDPServerSocket.recvfrom(bufferSize)
                message = message.decode('utf-8')

                #if the client requesting to close the connection - with interrupt
                if message == "Client requested shutdown - FIN":
                    print('Session finished with '+address[0])
                    # counter=0
                    break 
                
                #calcs server e for each packet
                if i==0:
                    server_e = message
                else:
                    server_e ="".join([chr(ord(a)^ord(b)) for a,b in zip(server_e,message)])
                
                #break the arrived message to sequence number and payload data
                message = message.split(" ",1)
                clientMsg = f"Server got message {message[0]} from {address[0]}:\n{message[1]}"

                #keep track of wich packets from d packets has arrived
                try:
                    seq_index = int(message[0][3::])
                    arrived_packages_flags[seq_index]=True
                except ValueError:
                    raise TimeoutException

                print(clientMsg)

                # Sending a reply to client
                msgFromServer = "Server recived packet " + message[0]
                sendMsg(msgFromServer,address)

            except TimeoutException:
                sendMsg('PACKET LOST',address)

        if server_e!=server_e_bu and arrived_packages_flags.count(False)!=1:
            updateDroppedList()
            if checkForExistsAttack():          #if the server recognized malicous activity
                sendMsg(WARNING_MSG,address)
            else:
                askForRetransmition()

    #The server send aprrove msg to close the connection with the client
    sendMsg(FIN_MSG,address)

    # if one packet was missing then the server can retrive it (by the rules of our protocol):
    if arrived_packages_flags.count(False)== 1 :
        server_e ="".join([chr(ord(a)^ord(b)) for a,b in zip(server_e,server_e_bu)])
        print("the missing packet is - " +server_e)
    UDPServerSocket.settimeout(None)