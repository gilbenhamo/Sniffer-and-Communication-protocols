from scapy.all import *
lastMsg = ''
def printLoad(packet):
    global lastMsg
    # if(pFlag):
    message = packet[Raw].load.decode('utf-8').split(' ',1)
    if lastMsg != message:
        split_msg = f"Seq num: {message[0][3::]}, msg: {message[1]}"
        print(split_msg)
    lastMsg=message

print("~Adversary now listening on port 12321~")
a=sniff(iface='ens33',filter = 'dst port 12321',prn=lambda x:printLoad(x))
#a.nsummary()
