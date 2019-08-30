from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ethernet
from ryu.lib.packet import udp
import aiocoap.message as Message
import socket
from struct import *
import threading
import time
import controller_job_manager
import json
import pickle

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

s3 = socket.socket(family=socket.AF_INET,type=socket.SOCK_DGRAM)
local = socket.gethostname()
call_port = 6003
call_address = (local,call_port)
reply_port = 6004
reply_address = (local,reply_port)
s3.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s3.bind(reply_address)

class controller_server():
    def __init__(self):
        self.server_list =  []
        self.buffer = []

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
        return False

class packet_buffer():
    def __init__(self):
        self.buffer = []
        self.lock_flag = 0
        self.lock_info = []
        self.timestamp = int(time.time())

    def unlock(self, unlock_info):
        if self.lock_info==unlock_info:
            self.lock_flag = 0
            return True
        else:
            self.lock_flag = 1
            return False

    def lock(self, lock_info):
        self.lock_info = lock_info
        self.lock_flag = 1

class packet_receiver(threading.Thread):
    def __init__(self, controller):
        threading.Thread.__init__(self)
        self.controller = controller
    def run(self):
        while True:
            data,addr = s.recvfrom(2048)
            pkt = packet.Packet(data)
            self.controller.buffer.append(pkt)

class controller_thread(threading.Thread):
    def __init__(self, controller, packet_buffer):
        threading.Thread.__init__(self)
        self.controller = controller
        self.packet_buffer = packet_buffer

    def  run(self):
        while True:
            if self.controller.buffer!=[]:
                pkt = self.controller.buffer[0]
                self.controller.buffer.pop(0)
                eth_header = pkt.get_protocol(ethernet.ethernet)
                ipv4_header = pkt.get_protocol(ipv4.ipv4)
                udp_header = pkt.get_protocol(udp.udp)
                if udp_header.dst_port==SERVER_UDP_PORT:
                    server1 = self.controller.find_server(eth_header.dst)
                    if server1!=False and server1.is_health():
                        server1.add_job(pkt[-1], eth_header.src, ipv4_header.src,udp_header.src_port)
                    if server1==False:
                        server1 =  controller_job_manager.controller_job_manager(ipv4_header.dst,eth_header.dst)
                        server1.set_unhealth()
                        server1.add_job(pkt[-1], eth_header.src, ipv4_header.src,udp_header.src_port)
                        self.controller.server_list.append(server1)
                else:
                    unlock_info = [eth_header.src, ipv4_header.src, eth_header.dst, ipv4_header.dst, udp_header.dst_port]
                    if self.packet_buffer.lock_flag==1:
                        print("lock is :",self.packet_buffer.unlock(unlock_info))
                    server1 = self.controller.find_server(eth_header.src)
                    if server1:
                        server1.add_reply(pkt[-1], eth_header.dst)




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
            if not self.controller.check_server_exist(eth_header.src):
                server1 =  controller_job_manager.controller_job_manager(ipv4_header.src,eth_header.src)
                self.controller.server_list.append(server1)
            else:
                server1 = self.controller.find_server(eth_header.src)
            server1.set_stamp()



class checkserver_thread(threading.Thread):
    def __init__(self,controller,packet_buffer):
        threading.Thread.__init__(self)
        self.controller = controller
        self.packet_buffer = packet_buffer

    def run(self):
        while True:
            for server1 in self.controller.server_list:
                if server1.job_list!=[] and server1.is_health()==False:
                    server2 = self.controller.findback_server(server1)
                    if server2!=False:
                        for j in server1.job_list:
                            for pkt in j.pkt:
                                tmp = [server1.mac, server1.ipv4, server2.mac, server2.ipv4, [j.mac, j.ipv4, j.port, pkt]]
                                self.packet_buffer.buffer.append(tmp)
                        self.controller.server_list.remove(server1)




class callreply_thread(threading.Thread):
    def __init__(self, packet_buffer):
        threading.Thread.__init__(self)
        self.packet_buffer = packet_buffer

    def run(self):
        while True:
            data,address = s3.recvfrom(2048)
            if data.decode()=='get':
                if self.packet_buffer.buffer!=[] and self.packet_buffer.lock_flag==0:
                    info = self.packet_buffer.buffer[0]
                    data = pickle.dumps(info)
                    s3.sendto(data,call_address)
                    lock_info = [info[2], info[3], info[4][0], info[4][1], info[4][2]]
                    self.packet_buffer.lock(lock_info)
                    print('packet send')
                    time.sleep(2)
                else:
                    data = pickle.dumps([])
                    s3.sendto(data,call_address)
            else:
                print('the message is wrong')




packet_buffer = packet_buffer()
controller = controller_server()
th1 = controller_thread(controller=controller, packet_buffer=packet_buffer)
th2 = heartbeat_thread(controller=controller)
th3 = packet_receiver(controller=controller)
th4 = checkserver_thread(controller=controller, packet_buffer=packet_buffer)
th5 = callreply_thread(packet_buffer=packet_buffer)
th1.start()
th2.start()
th3.start()
th4.start()
th5.start()
