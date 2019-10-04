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

with open('config.json','r') as config:
    config = json.load(config)

network_config = config["ryu_config"]["network_config"]
ryu_listen_port = network_config["ryu_listen_port"]

class myswitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS =  [ryu_event_base.EventMessage]

    def __init__(self, *args, **kwargs):
        super(myswitch, self).__init__(*args, **kwargs)
        self.name = 'packet_manager'

    @set_ev_cls(ryu_event_base.EventMessage)
    def redirection(self,ev):
        self.logger.info('listen start')
        # check buffer every time
        # set the socket config
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        local = socket.gethostname()
        listen_address = (local,ryu_listen_port)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(listen_address)
        # receive data from the port
        data,address = s.recvfrom(2048)
        self.logger.info('get data from controller server')
        data = pickle.loads(data)
        msg = data
        self.send_event('ryu_controller',ryu_event_base.EventMessage(msg))
