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
    h10 = net.addHost('h10', ip='no ip defined/8')
    h70 = net.addHost('h70', ip='no ip defined/8')
    h30 = net.addHost('h30', ip='no ip defined/8')
    h40 = net.addHost('h40', ip='no ip defined/8')
    h50 = net.addHost('h50', ip='no ip defined/8')
    h60 = net.addHost('h60', ip='no ip defined/8')
    dhcp_server = net.addHost('h20', ip='192.168.1.1/24')

    info("Create switch node.\n")
    s1 = net.addSwitch('s1',switch = OVSSwitch,failMode = 'secure',protocols = 'OpenFlow13')
    s2 = net.addSwitch('s2',switch = OVSSwitch,failMode = 'secure',protocols = 'OpenFlow13')
    s3 = net.addSwitch('s3',switch = OVSSwitch,failMode = 'secure',protocols = 'OpenFlow13')

    info("Create Links.\n")
    net.addLink(h10,s1,0,1)
    net.addLink(h70,s1,0,2)
    net.addLink(s1,s2,3,3)
    net.addLink(h30,s2,0,1)
    net.addLink(h40,s2,0,2)
    net.addLink(s2,s3,4,4)
    net.addLink(h50,s3,0,1)
    net.addLink(h60,s3,0,2)
    net.addLink(dhcp_server,s3,0,3)
#    net.addLink(dhcp_server,h1,0,0)

    info("Create Controller.\n")
    c0 = net.addController(name = 'c0',controller = RemoteController,ip = '127.0.0.1',port = 6633)

    info("Build and start network.\n")
    net.build()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])

    # become a dhcp server
    dhcp_server.cmd("~/bin/start_dhcp")

#    h10.cmd("dhclient")
#    h70.cmd("dhclient")
#    h30.cmd("dhclient")
#    h40.cmd("dhclient")
#    h50.cmd("dhclient")
#    h60.cmd("dhclient")

    net.start()
    info("Run mininet CLI.\n")
    CLI(net)

if __name__ == '__main__':
    setLogLevel('info')
    MininetTopo(sys.argv[1:])
