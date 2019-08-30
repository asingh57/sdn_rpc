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
        # this is for test
        self.tmp = {}

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
        datapath = ev.msg.datapath
        self.datapath = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # set table-miss for table 0
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(1)]
        self.add_flow(datapath=datapath, table_id=0, priority=0, match=match, instructions =inst)

        # set table-miss for table 1
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath=datapath, table_id=1, priority=0, match=match, actions=actions)

        # set coap packet_in
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
        ip_proto=inet.IPPROTO_UDP,udp_dst=5000)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(1)]
        self.add_flow(datapath=datapath, table_id=0, priority=1, match=match, instructions =inst)

        # set coap packet_in
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
        ip_proto=inet.IPPROTO_UDP,udp_src=5000)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(1)]
        self.add_flow(datapath=datapath, table_id=0, priority=1, match=match, instructions =inst)

        # set arp packet_in for controller
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REQUEST,
        arp_tpa = self.ipv4)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath=datapath, table_id=1, priority=2, match=match, actions=actions)

        # set regular packet_in for controller
        match = parser.OFPMatch(eth_dst  = self.mac, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=self.ipv4)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath=datapath, table_id=1, priority=2, match=match,actions=actions)

        # set icmp block in the begining
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=inet.IPPROTO_ICMP,
        icmpv4_type=icmp.ICMP_DEST_UNREACH, icmpv4_code=icmp.ICMP_PORT_UNREACH_CODE)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath=datapath, table_id=1, priority=3, match=match, actions=actions)

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
            icmp_header = pkt.get_protocols(icmp.icmp)
            if icmp_header!=[] and icmp_header[0].type==icmp.ICMP_DEST_UNREACH and icmp_header[0].code==icmp.ICMP_PORT_UNREACH_CODE:
                process = 1

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
                self.logger.info('get udp packet  to other client ')
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

        # check buffer
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        local = socket.gethostname()
        call_port = 6003
        call_address = (local,call_port)
        reply_port = 6004
        reply_address = (local,reply_port)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(call_address)
        data = 'get'
        s.sendto(data.encode(),reply_address)
        data,address = s.recvfrom(2048)
        data = pickle.loads(data)
        if data==[]:
            print('the buffer is empty')
        else:
            self.logger.info(data)
            old_mac = data[0]
            old_ipv4 = data[1]
            backup_mac = data[2]
            backup_ipv4 = data[3]
            job = data[4]
            job_mac=job[0]
            job_ipv4=job[1]
            job_port=job[2]
            pkt = job[3]
            jobdata = Message.decode(pkt)
            int_unpack = unpack("ii",jobdata.payload[0:8])
            count = int_unpack[0]
            # add redirection flow
            if count==0:
                match = parser.OFPMatch(eth_dst=old_mac, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=old_ipv4,
                ip_proto=inet.IPPROTO_UDP,udp_dst=5000)
                self.del_flow(datapath=datapath, table_id=0,  match=match)

                actions = [parser.OFPActionSetField(eth_dst=backup_mac),parser.OFPActionSetField(ipv4_dst=backup_ipv4)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(1)]
                match = parser.OFPMatch(eth_dst=old_mac, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=old_ipv4,
                ip_proto=inet.IPPROTO_UDP,udp_dst=5000)
                self.add_flow(datapath=datapath, table_id=0, priority=3, match=match, instructions =inst)

                actions = [parser.OFPActionSetField(eth_src=old_mac),parser.OFPActionSetField(ipv4_src=old_ipv4)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(1)]
                self.del_flow(datapath=datapath, table_id=0, instructions=inst)

                actions = [parser.OFPActionSetField(eth_src=old_mac),parser.OFPActionSetField(ipv4_src=old_ipv4)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(1)]
                match = parser.OFPMatch(eth_src=backup_mac, eth_type=ether_types.ETH_TYPE_IP, ipv4_src=backup_ipv4,
                ip_proto=inet.IPPROTO_UDP,udp_src=5000)
                self.add_flow(datapath=datapath, table_id=0, priority=3, match=match, instructions =inst)

            pkt_out = packet.Packet(pkt)
            pkt_out.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP, dst=backup_mac, src=job_mac))
            pkt_out.add_protocol(ipv4.ipv4(dst=backup_ipv4,src=job_ipv4,proto=inet.IPPROTO_UDP))
            pkt_out.add_protocol(udp.udp(src_port=job_port, dst_port=SERVER_UDP_PORT))
            pkt_out.serialize()
            self.logger.info(pkt_out)
            dpid = datapath.id
            out_port = self.mac_to_port[dpid][backup_mac]
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER), parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                                      data=pkt_out.data)
            datapath.send_msg(out)
            self.logger.info('packet out')

        # this is for test to check which flow is used
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch()
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                         0,ofp.OFPP_ANY, ofp.OFPG_ANY,
                                         cookie, cookie_mask,
                                         match)
        self.logger.info('send request')
        datapath.send_msg(req)



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

        # add regular packet
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # match2 = parser.OFPMatch(in_port=in_port,eth_src =src, eth_dst=dst, eth_type=ether_types.ETH_TYPE_IP,
            # ip_proto=inet.IPPROTO_UDP,udp_dst=5000)
            # match3 = parser.OFPMatch(in_port=in_port,eth_src =src, eth_dst=dst, eth_type=ether_types.ETH_TYPE_IP,
            # ip_proto=inet.IPPROTO_UDP,udp_src=5000)
            self.add_flow(datapath=datapath, table_id=1, priority=1, match=match, actions=actions)
            # self.add_flow(datapath=datapath, table_id=1, priority=2, match=match2, actions=actions2)
            # self.add_flow(datapath=datapath, table_id=1, priority=2, match=match3, actions=actions2)
            self.flow[src] = dst


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

        # regular packet handler
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
