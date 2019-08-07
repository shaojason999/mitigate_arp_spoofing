#!/usr/bin/env python
from scapy.all import *
import os

PCAP_SRC = '../pcaps/'
def trans_magic():
    os.system('cd ../pcaps; for i in `ls`; do sudo tshark -r $i -w $i -F libpcap > /dev/null; done; cd ../scripts')

def read_all_packets(switches):
    packets = None
    for name in switches:
        if packets == None:
            packets = rdpcap('{}{}.pcap'.format(PCAP_SRC, name))
          else:
            packets += rdpcap('{}{}.pcap'.format(PCAP_SRC, name))
    return packets

def read_LP(switches):
    size = 0
    packets = read_all_packets(switches)
    for packet in packets:
        eth = packet.getlayer(Ether)
        if eth.type == 0x600 or eth.type == 0x5ff:
            size += len(packet)

    print('LP/LRP total size: {} bytes'.format(size))
    return size

def read_ARP(switches):
    size = 0
    packets = read_all_packets(switches)
    for packet in packets:
        eth = packet.getlayer(Ether)
        if eth.type == 0x806:
            size += len(packet)

    print('ARP total size: {} bytes'.format(size))
    return size

def read_all(switches):
    size = 0
    packets = read_all_packets(switches)
    for packet in packets:
        size += len(packet)

    print("Total size: {} bytes".format(size))
    return size

def main():
    inner_ports = ['s10-eth3','s20-eth1','s20-eth2','s30-eth4']
    edge_ports = ['s10-eth1', 's10-eth2', 's30-eth1', 's30-eth2', 's30-eth3']
    host_ports = ['h10-eth0', 'h20-eth0', 'h30-eth0', 'h40-eth0']
#    controller = ['packet_in']
    print("###### Inner ports ######")
    read_LP(inner_ports)
    read_ARP(inner_ports)
    read_all(inner_ports)

    print("###### Inner ports + Edge ports ######")
    read_LP(inner_ports + edge_ports)
    read_ARP(inner_ports + edge_ports)
    read_all(inner_ports + edge_ports)

    print("###### s30-eth3 ######")
    read_LP(["s30-eth3"])
    read_ARP(["s30-eth3"])
    read_all(["s30-eth3"])

    print("###### Host ports ######")
    read_LP(host_ports)
    read_ARP(host_ports)
    read_all(host_ports)
    """
    print("###### Packet in ######")
    read_LP(controller)
    read_ARP(controller)
    read_all(controller)
    """

if __name__ == '__main__':
    print("Making sure the pcap magic number is correct")
#    trans_magic()
    print("Start")
    main()
