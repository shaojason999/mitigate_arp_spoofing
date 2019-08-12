from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER,MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.lib.packet import ethernet, arp, tcp, udp, dhcp, ipv4
from ryu.lib.packet import packet
from ryu.lib import pcaplib
from scapy.all import Ether


class TCP_RyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    lldp_struct = {}

    def __init__(self,*args,**kwargs):
        super(TCP_RyuApp,self).__init__(*args,**kwargs)
        self.pcap_writer = pcaplib.Writer(open('pcaps/packet_in.pcap','wb'))
        # set the topology(locaion) of the DHCP server
        self.DHCP_port = 3
        self.DHCP_dpid = 30
        self.DHCP_dp = []
        self.mac_to_dp = {}
        self.tranID_to_host = {}
        self.ip_to_mac = {}
        self.mac_to_ip = {}
        self.LP_learned = set()
        self.mac_to_port = {}

    def add_flow(self,datapath,priority,match,actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath = datapath,priority = priority,match = match,instructions = inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures,CONFIG_DISPATCHER)
    def switch_features_handler(self,ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        to_controller_action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        #DHCP
        ## port 67, 68 for DHCP; DHCP packets to CP rule.
        dhcp_to_server_match = parser.OFPMatch(eth_type = 0x0800,ip_proto=0x11,udp_dst=67)
        dhcp_to_client_match = parser.OFPMatch(eth_type = 0x0800,ip_proto=0x11,udp_dst=68)
        dhcp_to_client_match_for_DHCP_port = parser.OFPMatch(in_port = self.DHCP_port, eth_type = 0x0800,ip_proto=0x11,udp_dst=68)

        ## DHCP_dpid: the switch directly connected to DHCP server
        if dpid == self.DHCP_dpid: 
            self.add_flow(datapath,51,dhcp_to_client_match_for_DHCP_port,to_controller_action)
            self.DHCP_dp = datapath

        self.add_flow(datapath,50,dhcp_to_server_match,to_controller_action)
        self.add_flow(datapath,50,dhcp_to_client_match,[])


        # ARP packets to CP rule
        arp_request_match = parser.OFPMatch(eth_type=0x0806,arp_op=1)
        arp_reply_match = parser.OFPMatch(eth_type=0x0806,arp_op=2)
        self.add_flow(datapath,40,arp_request_match,to_controller_action)
        self.add_flow(datapath,40,arp_reply_match,[])

        # LP and LRP packets to CP rule
        LP_match = parser.OFPMatch(eth_type=0x5ff)
        LRP_match = parser.OFPMatch(eth_type=0x600)
        self.add_flow(datapath,30,LP_match,to_controller_action)
        self.add_flow(datapath,30,LRP_match,to_controller_action)

        # table-miss flow entry
        match = parser.OFPMatch()
        action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath,0,match,action)
       
 
    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        data = msg.data
        pkt = packet.Packet(data)
        pkt_ether = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_arp = pkt.get_protocol(arp.arp)

        self.pcap_writer.write_pkt(data)
        
        if not pkt_ether:
            return

        dst = pkt_ether.dst
        src = pkt_ether.src

        self.mac_to_port.setdefault(dpid,{})
        self.mac_to_port[dpid][src] = in_port

        # DHCP
        if pkt_ipv4:
            protocol = pkt_ipv4.proto
            if protocol == 0x11:    # udp
                pkt_udp = pkt.get_protocol(udp.udp)
                dst_port = pkt_udp.dst_port
                pkt_dhcp = pkt.get_protocol(dhcp.dhcp)
                xid = pkt_dhcp.xid
                if dst_port == 67:  # DHCP from client to server
                    self.tranID_to_host[xid] = src
                    self.mac_to_dp[src] = datapath

                    action = [parser.OFPActionOutput(self.DHCP_port)]   # controller to DHCP server
                    out = parser.OFPPacketOut(datapath = self.DHCP_dp,buffer_id = ofproto.OFP_NO_BUFFER,in_port = ofproto.OFPP_CONTROLLER,actions = action,data=data)
                    self.DHCP_dp.send_msg(out)
                    return
                elif dst_port == 68:
                    self.ip_to_mac[pkt_ipv4.src] = src  # record the DHCP's ip_to_mac match
                    self.mac_to_ip[src] = pkt_ipv4.src
                    self.mac_to_dp[src] = datapath

                    dst = self.tranID_to_host[xid]
                    datapath = self.mac_to_dp[dst]
                    port = self.mac_to_port[datapath.id][dst]

                    options = pkt_dhcp.options.option_list
                    for option in options:
                        if option.tag == 53:
                            if option.value == '\x05':    # DHCP ACK
                                self.ip_to_mac[pkt_dhcp.yiaddr] = dst   # record ip_to_mac match
                                self.mac_to_ip[dst] = pkt_dhcp.yiaddr

                    action = [parser.OFPActionOutput(port)] # controller to client
                    out = parser.OFPPacketOut(datapath = datapath,buffer_id = ofproto.OFP_NO_BUFFER,in_port = ofproto.OFPP_CONTROLLER,actions = action,data=data)
                    datapath.send_msg(out)
                    return

        # ARP
        ## handle ARP request
        if pkt_arp:
            dst_ip = pkt_arp.dst_ip
            src_ip = pkt_arp.src_ip
            if dst_ip not in self.ip_to_mac:
                print("match failed")
                return
            dst = self.ip_to_mac[dst_ip]


            # already learned LP/LRP, just send ARP reply
            if ((dst,src) in self.LP_learned) or ((src,dst) in self.LP_learned):
                pkt = packet.Packet()
                pkt.add_protocol(ethernet.ethernet(ethertype=0x806,
                    dst=src,src=dst))
                pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                    src_mac=dst,src_ip=dst_ip,
                    dst_mac=src,dst_ip=src_ip))
                self.send_packet(datapath,in_port,pkt)
                return
            else:
                # src and dst is belong to the same switch
                if self.mac_to_dp[src] == self.mac_to_dp[dst]:
                    # insert bi-directional flow entries
                    dst_port = self.mac_to_port[dpid][dst]
                    actions = [parser.OFPActionOutput(dst_port)]
                    match = parser.OFPMatch(in_port=in_port,eth_dst=dst)
                    self.add_flow(datapath,10,match,actions)

                    actions = [parser.OFPActionOutput(in_port)]
                    match = parser.OFPMatch(in_port=dst_port,eth_dst=src)
                    self.add_flow(datapath,10,match,actions)

                    # use the LP_learned to record
                    self.LP_learned.add((src,dst))
                    
                    # ARP reply 
                    pkt = packet.Packet()
                    pkt.add_protocol(ethernet.ethernet(ethertype=0x806,
                        dst=src,src=dst))
                    pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                        src_mac=dst,src_ip=dst_ip,
                        dst_mac=src,dst_ip=src_ip))
                    self.send_packet(datapath,in_port,pkt)
                    
                    return
                else:
                    # start to send LP
                    pkt = Ether(src=src,dst=dst,type=0x5ff)
                    pkt = str(pkt)
                    self.scapy_send_packet(datapath,ofproto.OFPP_FLOOD,pkt)
                    return

        # LRP; the dst of LRP is the src of LP
        if pkt_ether.ethertype == 0x600:
            print("LRP")
            print(src,dst)
            print(self.LP_learned)
            print((dst,src) in self.LP_learned)
            print((src,dst) in self.LP_learned)
            # insert bi-directional flow entries
            dst_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(dst_port)]
            match = parser.OFPMatch(in_port=in_port,eth_dst=dst)
            self.add_flow(datapath,10,match,actions)

            actions = [parser.OFPActionOutput(in_port)]
            match = parser.OFPMatch(in_port=dst_port,eth_dst=src)
            self.add_flow(datapath,10,match,actions)
            if datapath == self.mac_to_dp[dst]: # reach the dst(src of LP)
                ## it must add_protocol() in order: ethernet, then arp
                ## ARP reply to src
                dst_ip = self.mac_to_ip[dst]
                src_ip = self.mac_to_ip[src]
                dst_port = self.mac_to_port[dpid][dst]

                pkt = packet.Packet()
                pkt.add_protocol(ethernet.ethernet(ethertype=0x806,
                    dst=dst,src=src))
                pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                    src_mac=src,src_ip=src_ip,
                    dst_mac=dst,dst_ip=dst_ip))
                self.send_packet(datapath,dst_port,pkt)

                print("!!!!!!!!reach!!!!!!!!")

                self.LP_learned.add((src,dst))
                return
            else:
                print("!!!!!!!!not reach!!!!!!!!!!!")
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                actions = [parser.OFPActionOutput(dst_port)]
                out = parser.OFPPacketOut(datapath = datapath,buffer_id = msg.buffer_id,in_port = in_port,actions = actions,data=data)
                datapath.send_msg(out)
                return

        # LP
        if pkt_ether.ethertype == 0x5ff:
            print("LP")
            if datapath == self.mac_to_dp[dst]: # reach the dst
                # insert bi-directional flow entries
                dst_port = self.mac_to_port[dpid][dst]
                actions = [parser.OFPActionOutput(dst_port)]
                match = parser.OFPMatch(in_port=in_port,eth_dst=dst)
                self.add_flow(datapath,10,match,actions)

                actions = [parser.OFPActionOutput(in_port)]
                match = parser.OFPMatch(in_port=dst_port,eth_dst=src)
                self.add_flow(datapath,10,match,actions)

                # start to send LRP, use scapy module
                pkt = Ether(src=dst,dst=src,type=0x600)
                pkt = str(pkt)
                self.scapy_send_packet(datapath,in_port,pkt)
                return
            else:   # flooding
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                out = parser.OFPPacketOut(datapath = datapath,buffer_id = msg.buffer_id,in_port = in_port,actions = actions,data=data)
                datapath.send_msg(out)
                return
                           
    def send_packet(self,datapath,port,pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        action = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(datapath = datapath,buffer_id = ofproto.OFP_NO_BUFFER,in_port = ofproto.OFPP_CONTROLLER,actions = action,data=data)
        datapath.send_msg(out)


    def scapy_send_packet(self,datapath,port,pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        action = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(datapath = datapath,buffer_id = ofproto.OFP_NO_BUFFER,in_port = ofproto.OFPP_CONTROLLER,actions = action,data=pkt)
        datapath.send_msg(out)


