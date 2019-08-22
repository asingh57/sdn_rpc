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
import socket

SERVER_UDP_PORT = 5000
CLIENT_UDP_PORT = 5000

class myswitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(myswitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flow = {}
        self.server_list = ['00:00:00:00:00:01']
        self.count = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        self.logger.info("flow added %d", self.count)
        self.count = self.count +1
        datapath.send_msg(mod)

    def regular_packet_in(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get datapath id
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # read ethernet header
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src


        in_port = msg.match['in_port']

        # self.logger.info("regular packet in %s %s %s %s", dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        actions2 = [parser.OFPActionOutput(out_port),parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            match2 = parser.OFPMatch(in_port=in_port,eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=inet.IPPROTO_UDP,udp_dst=5000)
            match3 = parser.OFPMatch(in_port=in_port,eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=inet.IPPROTO_UDP,udp_src=5000)
            self.add_flow(datapath, 1, match, actions)
            self.add_flow(datapath, 2, match2, actions2)
            self.add_flow(datapath, 2, match3, actions2)
            self.flow[src] = dst


        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            pkt = packet.Packet(msg.data)
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            dst = eth_pkt.dst
            src = eth_pkt.src

            pkt = packet.Packet(msg.data)
            udp_header = pkt.get_protocols(udp.udp)
            if udp_header!=[]:
                if udp_header[0].src_port==SERVER_UDP_PORT or udp_header[0].dst_port==SERVER_UDP_PORT:
                    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                    server = (socket.gethostname(),12345)
                    s.sendto(msg.data,server)
                    s.close()
                    self.logger.info('get coap data')
            else:
                self.flow.setdefault(src,'')
                if dst!=self.flow[src]:
                    self.regular_packet_in(ev)
