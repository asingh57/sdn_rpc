from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ethernet
from ryu.lib.packet import udp
import socket
import aiocoap.message as message
from struct import *
import threading
import time
import server

SERVER_UDP_PORT = 5000

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
address = socket.gethostname()
port = 12345
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((address,port))

s2 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
address2 = socket.gethostname()
port2 = 12346
s2.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s2.bind((address2,port2))

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
            if backup.is_health() and backup.mac == server.mac:
                return backup
            else:
                return False

class thread1(threading.Thread):
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
                if not controller.check_server_exist(eth_header.dst):
                    server1 =  server.server(ipv4_header.dst,eth_header.dst)
                    controller.server_list.append(server1)
                server1 = controller.find_server(eth_header.dst)
                if True:
                    server1.add_job(pkt[-1])
                    # print("job_added")
                else:
                    if not controller.findback_server(server1)==False:
                        serverbackup = findback_server(server1)
                # print("receive_job")
            elif udp_header.src_port==SERVER_UDP_PORT:
                server1 = controller.find_server(eth_header.src)
                if server1:
                    server1.add_reply(pkt[-1])
                # print("receive_repley")



class thread2(threading.Thread):
    def __init__(self,controller):
        threading.Thread.__init__(self)
        self.controller = controller
    def run(self):
        while True:
            data,addr = s2.recvfrom(2048)
            print(data)

controller = controller_server()
th1 = thread1(controller=controller)
th2 = thread2(controller=controller)
th1.start()
th2.start()
