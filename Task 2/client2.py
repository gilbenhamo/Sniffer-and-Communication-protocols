
import random
import socket
from socket import timeout as TimeoutException
from time import sleep

MAX_BYTES = 100
PACKET_LOST_TIMEOUT = 5
RETRANSMISSION_MSG = 'Error - retransmission is nedded'
WARNING_MSG = 'WARNING - High probability of an Adversary attack'
HANDSHAKE_CREATED_MSG = 'Handshake created successfully'
msgFromClient = "The magic I evoked fifteen years ago means that Harry has powerful protection while he can still call this house home. However miserable he has been here, however unwelcome, however badly treated, you have at least, grudgingly, allowed him houseroom. This magic will cease to operate the moment that Harry turns seventeen; in other words, at the moment he becomes a man. I ask only this: that you allow Harry to return, once more, to this house, before his seventeenth birthday, which will ensure that the protection continues until that time. None of the Dursleys said anything. Dudley was frowning slightly, as though he was still trying to work out when he had ever been mistreated. Uncle Vernon looked as though he had something stuck in his throat; Aunt Petunia, however, was oddly flushed. Well, Harry . . . time for us to be off, said Dumbledore at last, standing up and straightening his long black cloak. Until we meet again, he said to the Dursleys, who looked as though that moment could wait forever as far as they were concerned"
#, and after doffing his hat, he swept from the room. Bye, said Harry hastily to the Dursleys, and followed Dumbledore, who paused beside Harry’s trunk, upon which Hedwig’s cage was perched. We do not want to be encumbered by these just now, he said, pulling out his wand again. I shall send them to the Burrow to await us there. However, I would like you to bring your Invisibility Cloak . . . just in case.
serverAddressPort = ("127.0.0.1", 12321)
bufferSize = 1024

def createMessagesList(d):
    msg_list = []
    seq_number = 0
    idx = 0
    for i in range(0,d):
        seq_str = f'sn:{str(seq_number)}'
        offset = MAX_BYTES - len(seq_str) - 1
        cur_msg = seq_str + " " + msgFromClient[idx:idx+offset]
        idx += offset
        seq_number += 1
        # Send to server using created UDP socket

        msg_list.append(cur_msg)
    return msg_list

def calc_e(msg_list):
    e = msg_list[0]
    for i in range(1,d):
        e ="".join([chr(ord(a)^ord(b)) for a,b in zip(e,msg_list[i])])
    return e

######### Handshake with the sever #########
# Create a UDP socket at client side
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPClientSocket.settimeout(PACKET_LOST_TIMEOUT)
handshake_flag = True
while handshake_flag:
    # calc d = number of messages to send 
    d = random.randrange(4, 10)
    # d=5

    # Create msg list with sequence number for each message 
    msg_list = createMessagesList(d)

    #calculate the XOR between all messages
    e=calc_e(msg_list)

    print("e is " +e)
    print("d is " + str(d))

    # Send e and d to server using created UDP socket
    bytesToSend = str.encode(str(d) + " " + e)
    UDPClientSocket.sendto(bytesToSend, serverAddressPort)
    transmission_flag = True
    try:
        msgFromServer = UDPClientSocket.recvfrom(bufferSize)
        msg = f"{msgFromServer[0].decode('utf-8')}"
        if msg == HANDSHAKE_CREATED_MSG:
            handshake_flag = False
    except TimeoutException:
        print('Retry to create handshake')
print(f'Handeshake with server (ip-{serverAddressPort[0]}) created successfully')
UDPClientSocket.settimeout(None)
######### Handshake created with the sever #########

while transmission_flag:
    try:
        transmission_flag = False
        #send d messages
        for i in range(0,d):
            sleep(3)

            cur_msg = msg_list[i]

            bytesToSend = str.encode(cur_msg)
            # Send to server using created UDP socket
            UDPClientSocket.sendto(bytesToSend, serverAddressPort)

            msgFromServer = UDPClientSocket.recvfrom(bufferSize)
            msg = f"{msgFromServer[0].decode('utf-8')}"
            if msg != 'PACKET LOST':
                print(msg) 

        #connection end or retransmission   
        msgFromServer = UDPClientSocket.recvfrom(bufferSize)
        msg = f"{msgFromServer[0].decode('utf-8')}"
        print(msg)
        if msg  == RETRANSMISSION_MSG: 
            transmission_flag = True
        elif msg == WARNING_MSG:
            pass
                    
    except KeyboardInterrupt:
        bytesToSend = str.encode("Client requested shutdown - FIN")
        UDPClientSocket.sendto(bytesToSend, serverAddressPort)

