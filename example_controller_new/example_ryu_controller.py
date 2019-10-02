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
import json
import sys
sys.path.append(r'../controller_api')
from ryu_controller_api import *
import ryu_event_base

# load the configuration data from config.json
with open('config.json','r') as config:
    config = json.load(config)

# configure the topology of whole network linked to this switch
network_config = config["ryu_config"]["network_config"]
ipv4_port = network_config["ipv4_port"]
ipv4_mac = network_config["ipv4_mac"]

class myswitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS =  [ryu_event_base.EventMessage]

    def __init__(self, *args, **kwargs):
        super(myswitch, self).__init__(*args, **kwargs)
        self.count = 0
        self.flag  = 0
        self.ipv4 = '10.10.10.10'
        self.mac = '66:66:66:66:66:66'
        self.datapath = []
        self.name = 'ryu_controller'
        # test
        self.config_flag=0
        #load the controller configuration data from configuration
        controller_config = config["controller_config"]["controller_config_list"]
        self.controller_list = {}
        for controller in controller_config:
            c = ryu_controller(controller)
            self.controller_list[controller["job_type"]] = c
    # add the basic flows for the switch
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("start adding flows")
        if self.config_flag==0:
            # get datapath information
            self.datapath = ev.msg.datapath
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
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
            actions = []
            self.add_flow(datapath=datapath, table_id=2, priority=0, match=match, actions=actions)

            # set coap request copy to controller
            for controller in list(self.controller_list.values()):
                server_port = controller.server_port
                coap_data_ipv4 = controller.coap_data_ipv4
                coap_data_port = controller.coap_data_port
                coap_data_mac = ipv4_mac[coap_data_ipv4]
                port = ipv4_port[coap_data_ipv4]
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_UDP,udp_dst=server_port)
                actions = [parser.OFPActionSetField(eth_dst=coap_data_mac),parser.OFPActionSetField(ipv4_dst=coap_data_ipv4),
                parser.OFPActionSetField(udp_dst=coap_data_port),parser.OFPActionOutput(port)]
                inst = [ parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
                self.add_flow(datapath=datapath, table_id=2, priority=3, match=match, instructions =inst)

            # set coap reply copy to controller
            for controller in list(self.controller_list.values()):
                server_port = controller.server_port
                coap_data_ipv4 = controller.coap_data_ipv4
                coap_data_port = controller.coap_data_port
                coap_data_mac = ipv4_mac[coap_data_ipv4]
                port = ipv4_port[coap_data_ipv4]
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_UDP,udp_src=server_port)
                actions = [parser.OFPActionSetField(eth_dst=coap_data_mac),parser.OFPActionSetField(ipv4_dst=coap_data_ipv4),
                parser.OFPActionSetField(udp_dst=coap_data_port),parser.OFPActionOutput(port)]
                inst = [ parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
                self.add_flow(datapath=datapath, table_id=2, priority=3, match=match, instructions =inst)

            # set icmp block in the begining
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=inet.IPPROTO_ICMP,
            icmpv4_type=icmp.ICMP_DEST_UNREACH, icmpv4_code=icmp.ICMP_PORT_UNREACH_CODE)
            actions = []
            self.add_flow(datapath=datapath, table_id=0, priority=100, match=match, actions=actions)

            # add flow based ipv4_mac
            for toipv4 in ipv4_mac:
                out_port = ipv4_port[toipv4]
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=toipv4)
                self.add_flow(datapath=datapath, table_id=1, priority=5, match=match,actions=actions)
                for controller in list(self.controller_list.values()):
                    # send one copy to table 2 and forward to  controller
                    server_port = controller.server_port
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(2)]
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=toipv4, ip_proto=inet.IPPROTO_UDP,udp_dst=server_port)
                    self.add_flow(datapath=datapath, table_id=1, priority=100, match=match,instructions=inst)
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(2)]
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=toipv4, ip_proto=inet.IPPROTO_UDP,udp_src=server_port)
                    self.add_flow(datapath=datapath, table_id=1, priority=100, match=match,instructions=inst)
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch( eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REQUEST, arp_tpa =toipv4 )
                self.add_flow(datapath=datapath, table_id=1, priority=50, match=match, actions=actions)
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_op = arp.ARP_REPLY, arp_tpa=toipv4)
                self.add_flow(datapath=datapath, table_id=1, priority=50, match=match, actions=actions)
            self.config_flag=1
        self.send_event('packet_manager',ryu_event_base.EventMessage())
    # get the event from packet manager and add redirection flows
    @set_ev_cls(ryu_event_base.EventMessage)
    def redirection(self,ev):
        data = ev.message
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # receive data from the port
        self.logger.info('get redirection command')

        if isinstance(data, list) and len(data)>0:
            self.logger.info(data)
            old_mac = data[0]
            old_ipv4 = data[1]
            backup_mac = data[2]
            backup_ipv4 = data[3]
            job = data[4]
            job_mac=job[0]
            job_ipv4=job[1]
            job_port=job[2]
            job_type = job[3]
            count = job[4]
            controller = self.controller_list[job_type]
            server_udp_port = controller.server_port
            # load the flows add before
            controller.redirection_oldmac.setdefault(job_mac,'')
            controller.redirection_oldipv4.setdefault(job_ipv4,'')
            controller.redirection_mac.setdefault(job_mac,'')
            controller.redirection_ipv4.setdefault(job_ipv4,'')
            if controller.redirection_mac[job_mac]=='' and controller.redirection_ipv4[job_ipv4]=='':
                controller.redirection_oldipv4[job_ipv4]=old_ipv4
                controller.redirection_oldmac[job_mac]=ipv4_mac[old_ipv4]
            # add redirection flow
            if count==0:
                old_ipv4 = controller.redirection_oldipv4[job_ipv4]
                old_mac = ipv4_mac[old_ipv4]
                old_backipv4 = controller.redirection_ipv4[job_ipv4]
                if old_backipv4!='':
                    old_backmac = ipv4_mac[old_backipv4]
                    # delete the oringal flow
                    actions = [parser.OFPActionSetField(eth_dst=old_backmac),parser.OFPActionSetField(ipv4_dst=old_backipv4)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(1)]
                    match = parser.OFPMatch(eth_dst=old_mac, eth_src=job_mac, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=old_ipv4, ipv4_src=job_ipv4,
                    ip_proto=inet.IPPROTO_UDP,udp_dst=server_udp_port)
                    self.del_flow(datapath=datapath, table_id=0, priority=3, instructions=inst,match=match)
                    # delete the oringal flow
                    actions = [parser.OFPActionSetField(eth_src=old_mac),parser.OFPActionSetField(ipv4_src=old_ipv4)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(1)]
                    match = parser.OFPMatch(eth_src=old_backmac, eth_dst=job_mac, eth_type=ether_types.ETH_TYPE_IP, ipv4_src=old_backipv4, ipv4_dst=job_ipv4,
                    ip_proto=inet.IPPROTO_UDP,udp_src=server_udp_port)
                    self.del_flow(datapath=datapath, table_id=0, priority=3, match=match,instructions=inst)

                if old_ipv4!=backup_ipv4:
                    # add new flow
                    actions = [parser.OFPActionSetField(eth_dst=backup_mac),parser.OFPActionSetField(ipv4_dst=backup_ipv4)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(1)]
                    match = parser.OFPMatch(eth_dst=old_mac, eth_src=job_mac, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=old_ipv4, ipv4_src=job_ipv4,
                    ip_proto=inet.IPPROTO_UDP,udp_dst=server_udp_port)
                    self.add_flow(datapath=datapath, table_id=0, priority=3, match=match, instructions =inst)
                    # add new flow
                    actions = [parser.OFPActionSetField(eth_src=old_mac),parser.OFPActionSetField(ipv4_src=old_ipv4)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions), parser.OFPInstructionGotoTable(1)]
                    match = parser.OFPMatch(eth_src=backup_mac, eth_dst=job_mac, eth_type=ether_types.ETH_TYPE_IP, ipv4_src=backup_ipv4, ipv4_dst=job_ipv4,
                    ip_proto=inet.IPPROTO_UDP,udp_src=server_udp_port)
                    self.add_flow(datapath=datapath, table_id=0, priority=3, match=match, instructions =inst)

                # record the flow change
                controller.redirection_ipv4[job_ipv4] = backup_ipv4
                controller.redirection_mac[job_mac] = ipv4_mac[backup_ipv4]

            self.send_event('packet_manager',ryu_event_base.EventMessage())

    # this will keep ryu application loop
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def keep_loop(self):
        self.logger.info("get packet")
        self.send_event('packet_manager',ryu_event_base.EventMessage())

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
    def del_flow(self, datapath,table_id, priority, match=[], instructions=[]):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if match==[] and instructions!=[]:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, priority=priority, command=ofproto.OFPFC_DELETE_STRICT,
                                                                    out_port=ofproto.OFPP_ANY,out_group=ofproto.OFPG_ANY, instructions=instructions)
        elif instructions==[] and match!=[]:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id,  priority=priority, command=ofproto.OFPFC_DELETE_STRICT,match = match,
                                                                    out_port=ofproto.OFPP_ANY,out_group=ofproto.OFPG_ANY)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id,  priority=priority,command=ofproto.OFPFC_DELETE_STRICT,match = match,
                                                                    out_port=ofproto.OFPP_ANY,out_group=ofproto.OFPG_ANY, instructions=instructions)
        self.count = self.count -1
        self.logger.info("flow deleted %d", self.count)
        datapath.send_msg(mod)
