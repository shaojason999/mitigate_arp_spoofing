from scapy.all import *
COUNT = 1000

pkt = Ether(src="66:cf:05:22:2c:f8", dst="ff:ff:ff:ff:ff:ff")/ARP(op=ARP.who_has, hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.2", hwsrc="66:cf:05:22:2c:f8", psrc="192.168.1.74" )

for _ in range(COUNT):
    sendp(pkt)
