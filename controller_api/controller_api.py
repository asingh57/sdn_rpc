import sys
import socket
sys.path.append(r'../controller_api')
from controller_server_api import *
from coap_handler_thread_api import *
from heartbeat_thread_api import *
from callreply_thread_api import *


class controller():
    def __init__(self,job_type,controller_ipv4,server_port,coap_handler_address,heartbeat_thread_address,call_address,ryu_listen_address,ipv4_mac):
        # the name of job
        self.job_type = job_type
        # the ipv4 address of controller server
        self.controller_ipv4 = controller_ipv4
        # the port that used to request
        self.server_port = server_port
        # the address to get coap data
        self.coap_handler_address = coap_handler_address
        # the address to get heartbeat
        self.heartbeat_thread_address = heartbeat_thread_address
        # the address to get the call
        self.call_address = call_address
        # the address  ryu listen to
        self.ryu_listen_address = ryu_listen_address
        # build the object of controller
        self.controller = controller_server(job_type,controller_ipv4,server_port,ipv4_mac)
        # use coap_handler_address to send packet
        self.buffer = packet_buffer(send_address=coap_handler_address[0])

    def creat_thread(self):
        # the coap_handler thread
        # the address is where to get coap packet
        self.coap_handler = coap_handler_thread(controller=self.controller, packet_buffer=self.buffer,
        address=self.coap_handler_address)
        # the heartbeat thread
        # the ade address is where to listen the heartbeat
        self.heartbeat = heartbeat_thread(controller=self.controller, packet_buffer=self.buffer,
        address=self.heartbeat_thread_address,  call_address=self.call_address, ryu_listen_address=self.ryu_listen_address)

    def run_controller(self):
        self.coap_handler.start()
        self.heartbeat.start()
