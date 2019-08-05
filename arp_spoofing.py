from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER,MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet

class TCP_RyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    lldp_struct = {}

    def __init__(self,*args,**kwargs):
        super(TCP_RyuApp,self).__init__(*args,**kwargs)
        # set the topology(locaion) of the DHCP server
        self.DHCP_port = 3
        self.DHCP_dpid = 3
        self.DHCP_dp = {}
        self.mac_to_port = {}
        self.tcp_info = {}

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

        # port 67, 68 for DHCP; DHCP packets to CP rule.
        dhcp_to_server_match = parser.OFPMatch(eth_type = 0x0800,ip_proto=0x11,udp_dst=67)
        dhcp_to_client_match = parser.OFPMatch(eth_type = 0x0800,ip_proto=0x11,udp_dst=68)
        dhcp_to_client_match_for_DHCP_port = parser.OFPMatch(in_port = self.DHCP_port, eth_type = 0x0800,ip_proto=0x11,udp_dst=68)

        # DHCP_dpid: the switch directly connected to DHCP server
        if dpid == self.DHCP_dpid: 
            self.add_flow(datapath,51,dhcp_to_client_match_for_DHCP_port,to_controller_action)
            self.DHCP_dp = datapath

        self.add_flow(datapath,50,dhcp_to_server_match,to_controller_action)
        self.add_flow(datapath,50,dhcp_to_client_match,[])


        # ARP packets to CP rule.
        arp_request_match = parser.OFPMatch(eth_type=0x0806,arp_op=1)
        arp_reply_match = parser.OFPMatch(eth_type=0x0806,arp_op=2)
        self.add_flow(datapath,100,arp_request_match,to_controller_action)
        self.add_flow(datapath,100,arp_reply_match,to_controller_action)

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

        if pkt_ipv4:
            protocol = pkt_ipv4.proto
            if protocol == 0x11:    # udp
                pkt_udp = pkt.get_protocol(udp.udp)
                dst_port = pkt_udp.dst_port
                if dst_port == 67:  # DHCP from client to server
                    action = [parser.OFPActionOutput(self.DHCP_port)]
                    out = parser.OFPPacketOut(datapath = self.DHCP_dp,buffer_id = ofproto.OFP_NO_BUFFER,in_port = ofproto.OFPP_CONTROLLER,actions = action,data=data)
                    print("client to server")
                elif dst_port == 68:
                    print("server to client")

        if pkt_arp:
            opcode = pkt_arp.opcode
#            print("arp_opcode:",opcode)

        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
#        actions = [parser.OFPActionOutput(in_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port = in_port,eth_dst=dst)
            self.add_flow(datapath,1,match,actions)

#        data = None
#        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
#            data = msg.data
        if pkt_arp:
            data="\xa2\xe4\xb1\xf3\x4e\xe5\xb6\xd3\xc5\x6d\xd9\x3c\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02\xb6\xd3\xc5\x6d\xd9\x3c\xc0\xa8\x01\x37\xa2\xe4\xb1\xf3\x4e\xe5\xc0\xa8\x01\x36"
            actions = [parser.OFPActionOutput(in_port)]
#            print("111")
        else:
            data=msg.data

#        a=msg.data.replace("\\x","").decode("hex")
#        print("123 ",data)

#        out = parser.OFPPacketOut(datapath = datapath,buffer_id = msg.buffer_id,in_port = in_port,actions = actions,data=data)
        out = parser.OFPPacketOut(datapath = datapath,buffer_id = ofproto.OFP_NO_BUFFER,in_port = in_port,actions = actions,data=data)
        datapath.send_msg(out)
    
    def handle_tcp(self,datapath,in_port,pkt_ipv4,pkt_tcp):
        self.tcp_info.setdefault(datapath.id,{})
        self.tcp_info[datapath.id].setdefault(pkt_ipv4.dst,{})
        self.tcp_info[datapath.id][pkt_ipv4.dst].setdefault(pkt_ipv4.src,0)
        self.tcp_info[datapath.id][pkt_ipv4.dst].setdefault('in_port',[])
        self.tcp_info[datapath.id][pkt_ipv4.dst][pkt_ipv4.src] += 1
        if in_port not in self.tcp_info[datapath.id][pkt_ipv4.dst]['in_port']:
            self.tcp_info[datapath.id][pkt_ipv4.dst]['in_port'].append(in_port)
        print(self.tcp_info)
                           
