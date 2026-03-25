#!/usr/bin/env python3
import sys
import os

from scapy.all import sniff, sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, TCP, UDP, DHCP, BOOTP

def handle_pkt(pkt):
	if TCP in pkt and pkt[TCP].dport == 1234:
		print("got a TCP packet")
	if UDP in pkt and pkt[UDP].dport == 67:
		print("got a DHCP packet")
	pkt.show2()

def main():
	ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
	iface = ifaces[0]
	print("sniffing on %s" % iface)
	sys.stdout.flush()
	sniff(iface = iface,
		prn = lambda x: handle_pkt(x))
	# sniff function passes the packet object as the one arg into prn: func

if __name__ == '__main__':
	main()