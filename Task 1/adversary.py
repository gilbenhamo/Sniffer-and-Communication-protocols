from scapy.all import *
pFlag = True
def printLoad(packet):
    global pFlag
    if(pFlag):
        message = packet[Raw].load.decode('utf-8').split(' ',1)
        split_msg = f"Seq num: {message[0][3::]}, msg: {message[1]}"
        print(split_msg)
    pFlag=not pFlag

print("~Adversary now listening to Localhost on port 12321~")
a=sniff(iface='lo',filter = 'dst port 12321',prn=lambda x:printLoad(x))
#a.nsummary()
