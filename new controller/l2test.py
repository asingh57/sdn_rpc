from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import in_proto as inet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import udp
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from aiocoap.message import Message
from struct import *
import socket
import pickle

SERVER_UDP_PORT = 5000

class myswitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(myswitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_to_ipv4 = {}
        self.mac_list = []
        self.flow = {}
        self.count = 0
        self.ipv4 = '10.10.10.10'
        self.mac = '66:66:66:66:66:66'
        self.redirection_mac = {}
        self.redirection_ipv4 = {}
        self.redirection_oldmac = {}
        self.redirection_oldipv4 = {}
        # this is for test
        self.tmp = {}
        self.flag  = 0

    # this is for test
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        for stat in ev.msg.body:
            key= str(stat.match)+str(stat.instructions)+str(stat.priority)+str(stat.table_id)
            if key not in self.tmp:
                self.tmp[key]=stat.packet_count
            elif self.tmp[key]< stat.packet_count:
                self.logger.info(stat)
                self.tmp[key]=stat.packet_count


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # get datapath information
        datapath = ev.msg.datapath
        self.datapath = datapath
        ofproto = ofproto_v1_3
        parser = datapath.ofproto_parser

        # set table-miss for table 0
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(1)]
        self.add_flow(datapath=datapath, table_id=0, priority=0, match=match, instructions =inst)

        # set table-miss for table 1
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(2)]
        self.add_flow(datapath=datapath, table_id=1, priority=0, match=match, instructions =inst)

        # set table-miss for table 2
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath=datapath, table_id=2, priority=0, match=match, actions=actions)

        # set coap packet_in
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
        ip_proto=inet.IPPROTO_UDP,udp_dst=5000)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(2)]
        self.add_flow(datapath=datapath, table_id=1, priority=1, match=match, instructions =inst)

        # set coap packet_in
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
        ip_proto=inet.IPPROTO_UDP,udp_src=5000)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(2)]
        self.add_flow(datapath=datapath, table_id=1, priority=1, match=match, instructions =inst)

        # set arp packet_in for controller
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REQUEST,
        arp_tpa = self.ipv4)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath=datapath, table_id=2, priority=2, match=match, actions=actions)

        # set regular packet_in for controller
        match = parser.OFPMatch(eth_dst  = self.mac, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=self.ipv4)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath=datapath, table_id=2, priority=3, match=match,actions=actions)

        # set icmp block in the begining
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=inet.IPPROTO_ICMP,
        icmpv4_type=icmp.ICMP_DEST_UNREACH , icmpv4_code=icmp.ICMP_PORT_UNREACH_CODE)
        actions = []
        self.add_flow(datapath=datapath, table_id=0, priority=3, match=match, actions=actions)

        # set the udp  broadcast
        match = parser.OFPMatch(eth_dst = 'ff:ff:ff:ff:ff:ff',eth_type=ether_types.ETH_TYPE_IP,
        ip_proto=inet.IPPROTO_UDP)
        actions = []
        self.add_flow(datapath=datapath, table_id=2, priority=101, match=match, actions=actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # packetin ethernet information
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth_header = pkt.get_protocol(ethernet.ethernet)
        dst = eth_header.dst
        src = eth_header.src
        in_port = msg.match['in_port']
        process = 0

        if process==0:
            # controller  packet_in handler
            arp_header = pkt.get_protocols(arp.arp)
            if arp_header!=[]:
                arp_header = arp_header[0]
                if arp_header.dst_ip==self.ipv4:
                    self.controller_packet_in(ev)
                    process = 1
            elif dst==self.mac:
                self.controller_packet_in(ev)
                process = 1

        if process==0:
            udp_header = pkt.get_protocols(udp.udp)
            # copy coap _packet_in handler
            if udp_header!=[] and eth_header.dst!=self.mac:
                # other packet_in handler
                # self.logger.info('get udp packet  to other client ')
                if udp_header[0].src_port==SERVER_UDP_PORT or udp_header[0].dst_port==SERVER_UDP_PORT:
                    if udp_header[0].src_port==SERVER_UDP_PORT:
                        self.logger.info('get reply')
                    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                    address = (socket.gethostname(),6001)
                    s.sendto(msg.data,address)
                    s.close()
                    self.logger.info('get coap data')
                    process = 1

        if process==0:
            # regular packet_in flow adder
            self.flow.setdefault(src,'')
            if dst!=self.flow[src]:
                self.regular_packet_in(ev)


        if self.flag==1:
            # check buffer every time
            # set the socket config
            s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            local = socket.gethostname()
            call_port = 6003
            call_address = (local,call_port)
            reply_port = 6004
            reply_address = (local,reply_port)
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.bind(call_address)
            # receive data from the port
            data = 'get'
            s.sendto(data.encode(),reply_address)
            self.logger.info('getsend')
            data,address = s.recvfrom(2048)
            data = pickle.loads(data)
            self.logger.info('get packet')
            if data!=[]:
                self.logger.info(data)
                old_mac = data[0]
                old_ipv4 = data[1]
                backup_mac = data[2]
                backup_ipv4 = data[3]
                job = data[4]
                job_mac=job[0]
                job_ipv4=job[1]
                job_port=job[2]
                count = job[3]
                pkt = job[4]

                self.redirection_oldmac.setdefault(job_mac,'')
                self.redirection_oldipv4.setdefault(job_ipv4,'')
                self.redirection_mac.setdefault(job_mac,'')
                self.redirection_ipv4.setdefault(job_ipv4,'')
                if self.redirection_mac[job_mac]=='' and self.redirection_ipv4[job_ipv4]=='':
                    self.redirection_oldmac[job_mac]=old_mac
                    self.redirection_oldipv4[job_ipv4]=old_ipv4
                # add redirection flow
                if count==0:
                    old_mac = self.redirection_oldmac[job_mac]
                    old_ipv4 = self.redirection_oldipv4[job_ipv4]
                    old_backmac = self.redirection_mac[job_mac]
                    old_backipv4 = self.redirection_ipv4[job_ipv4]
                    if old_backmac!='' and old_backipv4!='':
                        # delete the oringal flow
                        actions = [parser.OFPActionSetField(eth_dst=old_backmac),parser.OFPActionSetField(ipv4_dst=old_backipv4)]
                        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(1)]
                        self.del_flow(datapath=datapath, table_id=0, instructions=inst)
                        # delete the oringal flow
                        match = parser.OFPMatch(eth_src=old_backmac, eth_dst=job_mac, eth_type=ether_types.ETH_TYPE_IP, ipv4_src=old_backipv4, ipv4_dst=job_ipv4,
                        ip_proto=inet.IPPROTO_UDP,udp_src=5000)
                        self.del_flow(datapath=datapath, table_id=0, match=match)
                    # add new flow
                    actions = [parser.OFPActionSetField(eth_dst=backup_mac),parser.OFPActionSetField(ipv4_dst=backup_ipv4)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(1)]
                    match = parser.OFPMatch(eth_dst=old_mac, eth_src=job_mac, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=old_ipv4, ipv4_src=job_ipv4,
                    ip_proto=inet.IPPROTO_UDP,udp_dst=5000)
                    self.add_flow(datapath=datapath, table_id=0, priority=3, match=match, instructions =inst)
                    # add new flow
                    actions = [parser.OFPActionSetField(eth_src=old_mac),parser.OFPActionSetField(ipv4_src=old_ipv4)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(1)]
                    match = parser.OFPMatch(eth_src=backup_mac, eth_dst=job_mac, eth_type=ether_types.ETH_TYPE_IP, ipv4_src=backup_ipv4, ipv4_dst=job_ipv4,
                    ip_proto=inet.IPPROTO_UDP,udp_src=5000)
                    self.add_flow(datapath=datapath, table_id=0, priority=3, match=match, instructions =inst)
                    # record the flow change
                    self.redirection_mac[job_mac] = backup_mac
                    self.redirection_ipv4[job_ipv4] = backup_ipv4
                dpid = datapath.id
                out_port = self.mac_to_port[dpid][backup_mac]
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER), parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                                          data=pkt)
                datapath.send_msg(out)
                self.logger.info('packet out')
                self.flag = 0

        # this is for test to check which flow is used
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch()
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                         2,ofp.OFPP_ANY, ofp.OFPG_ANY,
                                         cookie, cookie_mask,
                                         match)
        self.logger.info('send request')
        datapath.send_msg(req)


    # add flow method: add flow at specific table with priority
    def add_flow(self, datapath, table_id, priority, match, actions = [], instructions = []):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if instructions!=[]:
            inst = instructions
        else:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, priority=priority,
                                match=match, instructions=inst)
        self.count = self.count +1
        self.logger.info("flow added %d", self.count)
        datapath.send_msg(mod)

    # delete flow method: use match or instructions to match the specific flow to delete
    def del_flow(self, datapath,table_id, match=[], instructions=[]):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if match==[] and instructions!=[]:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, command=ofproto.OFPFC_DELETE,
                                                                    out_port=ofproto.OFPP_ANY,out_group=ofproto.OFPG_ANY, instructions=instructions)
        elif instructions==[] and match!=[]:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, command=ofproto.OFPFC_DELETE,match = match,
                                                                    out_port=ofproto.OFPP_ANY,out_group=ofproto.OFPG_ANY)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, command=ofproto.OFPFC_DELETE,match = match,
                                                                    out_port=ofproto.OFPP_ANY,out_group=ofproto.OFPG_ANY, instructions=instructions)
        self.count = self.count -1
        self.logger.info("flow deleted %d", self.count)
        datapath.send_msg(mod)

    def regular_packet_in(self,ev):
        # get event information
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # read ethernet header
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src
        in_port = msg.match['in_port']

        # add to local data
        self.mac_to_port[dpid][src] = in_port
        if not src in self.mac_list:
            self.mac_list.append(src)
        if not dst in self.mac_list:
            self.mac_list.append(dst)

        # check if the out_mac is in the local data
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # add regular packet flow
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath=datapath, table_id=2, priority=100, match=match, actions=actions)
            self.flow[src] = dst

        #send the packet out
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

    def controller_packet_in(self, ev):
        # packetin information
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src
        in_port = msg.match['in_port']

        # arp packet handler
        arp_header = pkt.get_protocols(arp.arp)
        if arp_header!=[]:
            arp_header = arp_header[0]
            if arp_header.opcode == arp.ARP_REQUEST:
                self.logger.info("Receive ARP_REQUEST,request IP is %s",arp_header.dst_ip)
                pkt_out = packet.Packet()
                pkt_out.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype, dst=src, src=self.mac))
                pkt_out.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=self.mac, src_ip=self.ipv4, dst_mac=arp_header.src_mac,dst_ip=arp_header.src_ip))
                pkt_out.serialize()
                self.mac_to_ipv4[arp_header.src_mac] = arp_header.src_ip
                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                                          data=pkt_out.data)
                datapath.send_msg(out)

        # icmp packet handler
        icmp_header = pkt.get_protocols(icmp.icmp)
        if icmp_header!=[] and dst==self.mac:
            icmp_header =icmp_header[0]
            if icmp_header.type == icmp.ICMP_ECHO_REQUEST:
                ipv4_header = pkt.get_protocol(ipv4.ipv4)
                pkt_out = packet.Packet()
                pkt_out.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype, dst=src, src=self.mac))
                pkt_out.add_protocol(ipv4.ipv4(dst=ipv4_header.src,src=ipv4_header.dst,proto=ipv4_header.proto))
                pkt_out.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,code=icmp.ICMP_ECHO_REPLY_CODE,csum=0,data=icmp_header.data))
                pkt_out.serialize()
                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                                          data=pkt_out.data)
                datapath.send_msg(out)
                self.logger.info("Receive ICMP_ECHO_REQUEST,request IP is %s",ipv4_header.dst)

        # regular udp packet handler
        udp_header = pkt.get_protocols(udp.udp)
        eth_header = pkt.get_protocol(ethernet.ethernet)
        if udp_header!=[] and eth_header.dst==self.mac :
            self.logger.info('get udp packet to controller')
            udp_header = udp_header[0]
            s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            udp_port = udp_header.dst_port
            server = (socket.gethostname(),udp_port)
            s.sendto(msg.data,server)
            s.close()
            self.flag = 1
