from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER,MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import ethernet
#from ryu.lib.packet import ether_types
from ryu.lib.packet import arp, tcp, udp, dhcp, ipv4
from ryu.lib.packet import packet

class TCP_RyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    lldp_struct = {}

    def __init__(self,*args,**kwargs):
        super(TCP_RyuApp,self).__init__(*args,**kwargs)
        # set the topology(locaion) of the DHCP server
        self.DHCP_port = 3
        self.DHCP_dpid = 3
        self.DHCP_dp = []
        self.host_to_dp = {}
        self.tranID_to_host = {}
        self.ip_to_mac = {}
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
        flood_action = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

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


        # ARP packets to CP rule.
        arp_request_match = parser.OFPMatch(eth_type=0x0806,arp_op=1)
        arp_reply_match = parser.OFPMatch(eth_type=0x0806,arp_op=2)
        self.add_flow(datapath,40,arp_request_match,to_controller_action)
        self.add_flow(datapath,40,arp_reply_match,[])

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
                    self.host_to_dp[src] = datapath
                    action = [parser.OFPActionOutput(self.DHCP_port)]
                    out = parser.OFPPacketOut(datapath = self.DHCP_dp,buffer_id = ofproto.OFP_NO_BUFFER,in_port = ofproto.OFPP_CONTROLLER,actions = action,data=data)
                    self.DHCP_dp.send_msg(out)
                    print("client to server")
                    return
                elif dst_port == 68:
                    dst = self.tranID_to_host[xid]
                    datapath = self.host_to_dp[dst]
                    port = self.mac_to_port[datapath.id][dst]

                    options = pkt_dhcp.options.option_list
                    for option in options:
                        if option.tag == 53:
                            if option.value == '\x05':    # DHCP ACK
                                self.ip_to_mac[pkt_dhcp.yiaddr] = dst
                    action = [parser.OFPActionOutput(port)]
                    out = parser.OFPPacketOut(datapath = datapath,buffer_id = ofproto.OFP_NO_BUFFER,in_port = ofproto.OFPP_CONTROLLER,actions = action,data=data)
                    datapath.send_msg(out)
                    print("server to client")
                    print(self.ip_to_mac)
                    return

        # ARP
        ## ARP reply
        if pkt_arp:
            if pkt_arp.dst_ip not in self.ip_to_mac:
                return
            opcode = pkt_arp.opcode
            dst = self.ip_to_mac[pkt_arp.dst_ip]
            # it must add_protocol() in order: ethernet, then arp
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ether.ethertype,
                dst=src,src=dst))
            pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                src_mac=dst,src_ip=pkt_arp.dst_ip,
                dst_mac=pkt_arp.src_mac,dst_ip=pkt_arp.src_ip))
            self.send_packet(datapath,in_port,pkt)
            return
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port = in_port,eth_dst=dst)
            self.add_flow(datapath,1,match,actions)

#        data = None
#        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
#            data = msg.data


#        out = parser.OFPPacketOut(datapath = datapath,buffer_id = msg.buffer_id,in_port = in_port,actions = actions,data=data)
        out = parser.OFPPacketOut(datapath = datapath,buffer_id = ofproto.OFP_NO_BUFFER,in_port = in_port,actions = actions,data=data)
        datapath.send_msg(out)
    
                           
    def send_packet(self,datapath,port,pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print(pkt)
        pkt.serialize()
        print(pkt)
        data = pkt.data
        print(data)
        action = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(datapath = datapath,buffer_id = ofproto.OFP_NO_BUFFER,in_port = ofproto.OFPP_CONTROLLER,actions = action,data=data)
        datapath.send_msg(out)



