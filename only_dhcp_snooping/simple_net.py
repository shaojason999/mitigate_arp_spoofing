# ex : sudo python simple_net.py

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.link import Link, TCLink
import sys, getopt

def MininetTopo(argv):
    
#    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)
    net = Mininet()

    info("Create host nodes.\n")
    h10 = net.addHost('h10', ip='no ip defined/8', mac='00:00:00:00:00:01')
    h20 = net.addHost('h20', ip='no ip defined/8', mac='00:00:00:00:00:02')
    h30 = net.addHost('h30', ip='no ip defined/8', mac='00:00:00:00:00:03')
    h40 = net.addHost('h40', ip='no ip defined/8', mac='00:00:00:00:00:04')
    hosts = ['h10','h20','h30','h40']
    dhcp_server = net.addHost('h50', ip='192.168.1.1/24')

    info("Create switch node.\n")
    s10 = net.addSwitch('s10',switch = OVSSwitch,failMode = 'secure',protocols = 'OpenFlow13')
    s20 = net.addSwitch('s20',switch = OVSSwitch,failMode = 'secure',protocols = 'OpenFlow13')
    s30 = net.addSwitch('s30',switch = OVSSwitch,failMode = 'secure',protocols = 'OpenFlow13')

    info("Create Links.\n")
    net.addLink(h10,s10,0,1)
    net.addLink(h20,s10,0,2)
    net.addLink(s10,s20,3,1)
    net.addLink(s20,s30,2,4)
    net.addLink(h30,s30,0,1)
    net.addLink(h40,s30,0,2)
    net.addLink(dhcp_server,s30,0,3)    # DHCP must be h50-eth0
#    net.addLink(dhcp_server,h1,0,0)

    info("Create Controller.\n")
    c0 = net.addController(name = 'c0',controller = RemoteController,ip = '127.0.0.1',port = 6633)

    info("Build and start network.\n")
    net.build()
    s10.start([c0])
    s20.start([c0])
    s30.start([c0])

    # start dhcp server
    dhcp_server.cmd("~/bin/start_dhcp")

#    for host in hosts:
#        host.cmd("~/bin/dump")
#        host.cmd("dhclient -r")
#        host.cmd("dhclient")

    print("switch dump set")
    s10.cmd("~/bin/dump s10-eth1")
    s10.cmd("~/bin/dump s10-eth2")
    s10.cmd("~/bin/dump s10-eth3")
    s20.cmd("~/bin/dump s20-eth1")
    s20.cmd("~/bin/dump s20-eth2")
    s30.cmd("~/bin/dump s30-eth1")
    s30.cmd("~/bin/dump s30-eth2")
    s30.cmd("~/bin/dump s30-eth3")
    s30.cmd("~/bin/dump s30-eth4")

    print("host dump set" )
    h10.cmd("~/bin/dump")
    h20.cmd("~/bin/dump")
    h30.cmd("~/bin/dump")
    h40.cmd("~/bin/dump")

    print("dhcp release")
    h10.cmd("dhclient -r")
    h20.cmd("dhclient -r")
    h30.cmd("dhclient -r")
    h40.cmd("dhclient -r")

    print("dhcp request")
    h10.cmd("dhclient")
    h20.cmd("dhclient")
    h30.cmd("dhclient")
    h40.cmd("dhclient")

    print "start"
    net.start()
    info("Run mininet CLI.\n")
    CLI(net)
    h10.cmd("kill `pidof SCREEN`")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    MininetTopo(sys.argv[1:])
