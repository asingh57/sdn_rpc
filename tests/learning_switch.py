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
ipv4_port = {'10.0.0.1':1,'10.0.0.2':2,'10.0.0.3':3}
ipv4_mac =  {'10.0.0.1':'00:E0:4C:69:CA:6D','10.0.0.2':'00:E0:4C:36:23:2C'}

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
    # @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    # def flow_stats_reply_handler(self, ev):
    #  for stat in ev.msg.body:
    #      key= str(stat.match)+str(stat.instructions)+str(stat.priority)+str(stat.table_id)
    #      if key not in self.tmp:
    #          self.tmp[key]=stat.packet_count
    #      elif self.tmp[key]< stat.packet_count:
    #          self.logger.info(stat)
    #          self.tmp[key]=stat.packet_count


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # get datapath information
        datapath = ev.msg.datapath
        self.datapath = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #mannully add the flow
        # 1------->2
        actions = [parser.OFPActionOutput(2)]
        match = parser.OFPMatch(in_port=1,eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='10.0.0.2')
        self.add_flow(datapath=datapath, table_id=0, priority=1, match=match, actions=actions)
        match = parser.OFPMatch(in_port=1, eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REQUEST,
        arp_tpa ='10.0.0.2' )
        self.add_flow(datapath=datapath, table_id=0, priority=2, match=match, actions=actions)
        match = parser.OFPMatch(in_port=1, eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REPLY,
        arp_tpa='10.0.0.2')
        self.add_flow(datapath=datapath, table_id=0, priority=2, match=match, actions=actions)
        # 1------->3
        actions = [parser.OFPActionOutput(3)]
        match = parser.OFPMatch(in_port=1,eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='10.0.0.3')
        self.add_flow(datapath=datapath, table_id=0, priority=1, match=match, actions=actions)
        match = parser.OFPMatch(in_port=1, eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REQUEST,
        arp_tpa ='10.0.0.3' )
        self.add_flow(datapath=datapath, table_id=0, priority=2, match=match, actions=actions)
        match = parser.OFPMatch(in_port=1, eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REPLY,
        arp_tpa='10.0.0.3')
        self.add_flow(datapath=datapath, table_id=0, priority=2, match=match, actions=actions)
        # 2------->1
        actions = [parser.OFPActionOutput(1)]
        match = parser.OFPMatch(in_port=2,eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='10.0.0.1')
        self.add_flow(datapath=datapath, table_id=0, priority=1, match=match, actions=actions)
        match = parser.OFPMatch(in_port=2, eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REQUEST,
        arp_tpa ='10.0.0.1' )
        self.add_flow(datapath=datapath, table_id=0, priority=2, match=match, actions=actions)
        match = parser.OFPMatch(in_port=2, eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REPLY,
        arp_tpa='10.0.0.1')
        self.add_flow(datapath=datapath, table_id=0, priority=2, match=match, actions=actions)
        # 2------->3
        actions = [parser.OFPActionOutput(3)]
        match = parser.OFPMatch(in_port=2,eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='10.0.0.3')
        self.add_flow(datapath=datapath, table_id=0, priority=1, match=match, actions=actions)
        match = parser.OFPMatch(in_port=2, eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REQUEST,
        arp_tpa ='10.0.0.3' )
        self.add_flow(datapath=datapath, table_id=0, priority=2, match=match, actions=actions)
        match = parser.OFPMatch(in_port=2, eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REPLY,
        arp_tpa='10.0.0.3')
        self.add_flow(datapath=datapath, table_id=0, priority=2, match=match, actions=actions)
        # 3------->1
        actions = [parser.OFPActionOutput(1)]
        match = parser.OFPMatch(in_port=3,eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='10.0.0.1')
        self.add_flow(datapath=datapath, table_id=0, priority=1, match=match, actions=actions)
        match = parser.OFPMatch(in_port=3, eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REQUEST,
        arp_tpa ='10.0.0.1' )
        self.add_flow(datapath=datapath, table_id=0, priority=2, match=match, actions=actions)
        match = parser.OFPMatch(in_port=3, eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REPLY,
        arp_tpa='10.0.0.1')
        self.add_flow(datapath=datapath, table_id=0, priority=2, match=match, actions=actions)
        # 3------->2
        actions = [parser.OFPActionOutput(2)]
        match = parser.OFPMatch(in_port=3,eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='10.0.0.2')
        self.add_flow(datapath=datapath, table_id=0, priority=1, match=match, actions=actions)
        match = parser.OFPMatch(in_port=3, eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REQUEST,
        arp_tpa ='10.0.0.2' )
        self.add_flow(datapath=datapath, table_id=0, priority=2, match=match, actions=actions)
        match = parser.OFPMatch(in_port=3, eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REPLY,
        arp_tpa='10.0.0.2')
        self.add_flow(datapath=datapath, table_id=0, priority=2, match=match, actions=actions)

        match = parser.OFPMatch()
        actions = []
        self.add_flow(datapath=datapath, table_id=0, priority=0, match=match, actions=actions)

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
