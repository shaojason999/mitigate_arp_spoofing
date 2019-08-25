from scapy.all import *
import time

pkt = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")/ARP(op=ARP.who_has, hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.93", hwsrc="00:00:00:00:00:01", psrc="192.168.1.96" )

t1 = time.time()
sendp(pkt,count=1000,inter=1./1000,verbose=False)
print("Time elapsed: {}".format(time.time()-t1))
