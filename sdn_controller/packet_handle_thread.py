from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ethernet
from ryu.lib.packet import udp
import aiocoap.message as message
import socket
from struct import *
import threading
import time
import server
import json

SERVER_UDP_PORT = 5000

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
address = socket.gethostname()
port = 6001
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((address,port))

s2 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
address2 = socket.gethostname()
port2 = 6002
s2.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s2.bind((address2,port2))

s3 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
address3 = socket.gethostname()
port3 = 6004
s3.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s3.bind((address3,port3))

class controller_server():
    def __init__(self):
        self.server_list =  []

    def check_server_exist(self, mac):
        if self.server_list==[]:
            return False
        else:
            for server in self.server_list:
                if server.mac==mac:
                    return True
            return False

    def find_server(self, mac):
        for server in self.server_list:
            if server.mac==mac:
                return server
        return False

    def findback_server(self, server):
        for backup in self.server_list:
            if backup.is_health() and backup.mac != server.mac:
                return backup
            else:
                return False

class controller_thread(threading.Thread):
    def __init__(self, controller):
        threading.Thread.__init__(self)
        self.controller = controller
    def  run(self):
        while True:
            data,addr = s.recvfrom(2048)
            pkt = packet.Packet(data)
            eth_header = pkt.get_protocol(ethernet.ethernet)
            ipv4_header = pkt.get_protocol(ipv4.ipv4)
            udp_header = pkt.get_protocol(udp.udp)
            if udp_header.dst_port==SERVER_UDP_PORT:
                server1 = controller.find_server(eth_header.dst)
                if server1!=False and server1.is_health():
                    print("job_added to ", server1.mac)
                    server1.add_job(pkt[-1], eth_header.src, ipv4_header.src)
            elif udp_header.src_port==SERVER_UDP_PORT:
                server1 = controller.find_server(eth_header.src)
                if server1:
                    server1.add_reply(pkt[-1])



class heartbeat_thread(threading.Thread):
    def __init__(self,controller):
        threading.Thread.__init__(self)
        self.controller = controller
    def run(self):
        while True:
            data,addr = s2.recvfrom(2048)
            pkt = packet.Packet(data)
            eth_header = pkt.get_protocol(ethernet.ethernet)
            ipv4_header = pkt.get_protocol(ipv4.ipv4)
            udp_header = pkt.get_protocol(udp.udp)
            if not controller.check_server_exist(eth_header.src):
                server1 =  server.server(ipv4_header.src,eth_header.src)
                controller.server_list.append(server1)
            else:
                server1 = controller.find_server(eth_header.src)
            server1.set_stamp()

class sendpacket_thread(threading.Thread):
    def __init__(self, controller):
        threading.Thread.__init__(self)
        self.controller = controller

    def run(self):
        while True:
            for server1 in controller.server_list:
                if not server1.is_health():
                    server2 = controller.findback_server(server1)
                    if server2!=False:
                        data = [server1.mac,server1.ipv4,server2.mac,server2.ipv4]
                        for j in server1.job_list:
                            tmp = [j.mac, j.ipv4,j.pkt]
                            data.append(tmp)
                        out = json.dumps(data)
                        s3.sendto(out, (socket.gethostname(),6004))
            data = 'hi'
            s3.sendto(data.encode(),(socket.gethostname(),6004))




controller = controller_server()
th1 = controller_thread(controller=controller)
th2 = heartbeat_thread(controller=controller)
th3 = sendpacket_thread(controller=controller)
th1.start()
th2.start()
th3.start()
