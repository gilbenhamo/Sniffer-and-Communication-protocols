from scapy.all import *
import sys
import os
import time
from scapy.all import *

#choose wich packet the adversary want to drop
sequence_number = input("Enter desired sequence numbers to drop: ")
seq_list = sequence_number.split(' ')
for x in seq_list:
	ip_table_cmd = 'iptables -A INPUT -m string --algo bm --string sn:' + x + ' -j DROP'
	os.system(ip_table_cmd)
pFlag = True

#Func to print the packet payload
def printLoad(packet):
	global pFlag
	if(pFlag):
		message = packet[Raw].load.decode('utf-8').split(' ',1)
		split_msg = f"Seq num: {message[0][3::]}, msg: {message[1]}"
		print(split_msg)
	pFlag=not pFlag

print("~Adversary now listening to Localhost on port 12321~")
a=sniff(iface='lo',filter = 'dst port 12321',prn=lambda x:printLoad(x))
os.system('iptables -F')


