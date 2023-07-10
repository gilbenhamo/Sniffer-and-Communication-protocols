import socket
from time import sleep

MAX_BYTES = 100
msgFromClient = "The magic I evoked fifteen years ago means that Harry has powerful protection while he can still call this house home. However miserable he has been here, however unwelcome, however badly treated, you have at least, grudgingly, allowed him houseroom. This magic will cease to operate the moment that Harry turns seventeen; in other words, at the moment he becomes a man. I ask only this: that you allow Harry to return, once more, to this house, before his seventeenth birthday, which will ensure that the protection continues until that time. None of the Dursleys said anything. Dudley was frowning slightly, as though he was still trying to work out when he had ever been mistreated. Uncle Vernon looked as though he had something stuck in his throat; Aunt Petunia, however, was oddly flushed. Well, Harry . . . time for us to be off, said Dumbledore at last, standing up and straightening his long black cloak. Until we meet again, he said to the Dursleys, who looked as though that moment could wait forever as far as they were concerned"
#, and after doffing his hat, he swept from the room. Bye, said Harry hastily to the Dursleys, and followed Dumbledore, who paused beside Harry’s trunk, upon which Hedwig’s cage was perched. We do not want to be encumbered by these just now, he said, pulling out his wand again. I shall send them to the Burrow to await us there. However, I would like you to bring your Invisibility Cloak . . . just in case.
seq_number = 0
idx = 0


serverAddressPort = ("127.0.0.1", 12321)

bufferSize = 1024

# Create a UDP socket at client side
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)


while True:
    seq_str = f'sn:{str(seq_number)}'
    offset = MAX_BYTES - len(seq_str) - 1
    sleep(3)
    cur_msg = seq_str + " " + msgFromClient[idx:idx+offset]
    idx += offset
    seq_number += 1
    bytesToSend = str.encode(cur_msg)
    # Send to server using created UDP socket
    UDPClientSocket.sendto(bytesToSend, serverAddressPort)

    msgFromServer = UDPClientSocket.recvfrom(bufferSize)
    msg = f"{msgFromServer[0].decode('utf-8')}"
    print(msg)

    if idx > len(msgFromClient):
        break

