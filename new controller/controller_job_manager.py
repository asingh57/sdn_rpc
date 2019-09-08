from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ethernet
from ryu.lib.packet import udp
from aiocoap.message import Message
import socket
from struct import *
import threading
import time
import controller_job_manager
from controller_job_manager import getrawpacket
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

controller_lock = threading.Lock()
packet_buffer_lock = threading.Lock()



class controller_server():
    def __init__(self):
        self.server_list =  []

    def check_server_exist(self, ipv4):
        for server in self.server_list:
            if server.ipv4==ipv4:
                return True
        return False

    def find_server(self, ipv4):
        for server in self.server_list:
            if server.ipv4==ipv4:
                return server
        return False

    def findback_server(self, server=[]):
        if server==[] and len(self.server_list)>=1:
            return self.server_list[0]
        else:
            for backup in self.server_list:
                if backup.is_health() and backup.ipv4 != server.ipv4:
                    return backup
        return False


class packet_buffer():
    def __init__(self):
        self.buffer = []
        self.lock_flag = 0
        self.lock_info = []
        self.temp_packet = []

    def unlock(self, unlock_info):
        if self.lock_info==unlock_info:
            self.buffer.pop(0)
            self.lock_flag = 0
            return True
        else:
            self.lock_flag = 1
            return False

    def lockfun(self, lock_info):
        self.lock_info = lock_info
        self.lock_flag = 1

class controller_thread(threading.Thread):
    def __init__(self, controller, packet_buffer):
        threading.Thread.__init__(self)
        self.controller = controller
        self.packet_buffer = packet_buffer

    def  run(self):
        while True:
            data,addr = s.recvfrom(2048)
            pkt = packet.Packet(data)
            eth_header = pkt.get_protocol(ethernet.ethernet)
            ipv4_header = pkt.get_protocol(ipv4.ipv4)
            udp_header = pkt.get_protocol(udp.udp)
            jobdata = Message.decode(pkt[-1])
            int_unpack = unpack("ii",jobdata.payload[0:8])
            count = int_unpack[0]
            job_id = int_unpack[1]
            if udp_header.dst_port==SERVER_UDP_PORT:
                server1 = self.controller.find_server(ipv4_header.dst)
                if server1==False and count==0:
                    server2 = self.controller.findback_server()
                    if server2!=False:
                        pkt_out = getrawpacket(eth_header.src, server2.mac,ipv4_header.src, server2.ipv4, udp_header.src_port,SERVER_UDP_PORT,pkt[-1])
                        tmp = [eth_header.dst,ipv4_header.dst, server2.mac, server2.ipv4, [eth_header.src,ipv4_header.src,udp_header.src_port,0,pkt_out]]
                        with packet_buffer_lock:
                            # print("the packet_buffer_lock is locked by adding packet in to buffer2")
                            self.packet_buffer.buffer.append(tmp)
                        with controller_lock:
                            # print("the controller lock is locked by adding packet in to server")
                            server2.add_job(pkt[-1], eth_header.src, ipv4_header.src,udp_header.src_port)
                if server1!=False and server1.is_health():
                    # the job_id is not unique by now
                    with controller_lock:
                        server1.add_job(pkt[-1], eth_header.src, ipv4_header.src,udp_header.src_port)
            else:
                unlock_info =  [ipv4_header.dst, udp_header.dst_port]
                if self.packet_buffer.lock_flag==1:
                    with packet_buffer_lock:
                        # print("the packet_buffer_lock is locked by adding reply")
                        result = self.packet_buffer.unlock(unlock_info)
                    if result:
                        print("The reply is received and unlock the lock")
                    else:
                        print("The reply is not for lock")
                with controller_lock:
                    # print("the controller_lock is locked by adding reply")
                    server1 = self.controller.find_server(eth_header.src)
                    if server1:
                        server1.add_reply(pkt[-1], ipv4_dst)

class heartbeat_thread(threading.Thread):
    def __init__(self,controller,packet_buffer):
        threading.Thread.__init__(self)
        self.controller = controller
        self.packet_buffer = packet_buffer

    def run(self):
        while True:
            data,addr = s2.recvfrom(2048)
            pkt = packet.Packet(data)
            eth_header = pkt.get_protocol(ethernet.ethernet)
            ipv4_header = pkt.get_protocol(ipv4.ipv4)
            udp_header = pkt.get_protocol(udp.udp)
            if  self.controller.check_server_exist(ipv4_header.src)==False:
                server1 =  controller_job_manager.controller_job_manager(ipv4_header.src,eth_header.src)
                with controller_lock:
                    # print("the controller_lock is locked by adding new server by heartbeat")
                    self.controller.server_list.append(server1)
                # print(server1.ipv4, "is added to the list" )
            else:
                server1 = self.controller.find_server(ipv4_header.src)
            with controller_lock:
                # print("the controller_lock is locked by setting the stamp of server")
                server1.set_stamp()
            for server1 in self.controller.server_list:
                if server1.is_health()==False and server1.job_list==[]:
                    with controller_lock:
                        print("the controller_lock is locked by removing the server from list because empty")
                        self.controller.server_list.remove(server1)
                    print("The server ",server1.ipv4,"is no longer working")
                if server1.job_list!=[] and server1.is_health()==False:
                    server2 = self.controller.findback_server(server1)
                    if server2!=False:
                        with controller_lock:
                            for j in server1.job_list:
                                count = 0
                                print("job count ", j.count,"job pkt", len(j.pkt))
                                for pkt in list(j.pkt.values()):
                                    print(pkt)
                                    pkt = getrawpacket(j.mac, server2.mac, j.ipv4, server2.ipv4, j.port, SERVER_UDP_PORT,pkt)
                                    tmp = [server1.mac, server1.ipv4, server2.mac, server2.ipv4, [j.mac, j.ipv4, j.port,count, pkt]]
                                    with packet_buffer_lock:
                                        print("the packet_buffer_lock is locked by adding packet in to buffer1")
                                        self.packet_buffer.buffer.append(tmp)
                                    count +=1
                        with controller_lock:
                            print("the controller_lock is locked by removing the server from list after moving job")
                            self.controller.server_list.remove(server1)
                        print("The job in ",server1.ipv4,"is move in to ",server2.ipv4)


class callreply_thread(threading.Thread):
    def __init__(self,  packet_buffer):
        threading.Thread.__init__(self)
        self.packet_buffer = packet_buffer

    def run(self):
        while True:
                data,address = s3.recvfrom(2048)
                if data.decode()=='get':
                    print("buffer size",len(self.packet_buffer.buffer))
                    if self.packet_buffer.buffer!=[] and self.packet_buffer.lock_flag==0:
                        with packet_buffer_lock:
                            print("the packet_buffer_lock is locked by load buffer")
                            info = self.packet_buffer.buffer[0]
                        data = pickle.dumps(info)
                        s3.sendto(data,call_address)
                        lock_info = [info[4][1], info[4][2]]
                        self.packet_buffer.lockfun(lock_info)
                        self.packet_buffer.temp_packet = data
                        print('packet send and wait for the reply to unlock')
                    elif self.packet_buffer.lock_flag==1:
                        data = self.packet_buffer.temp_packet
                        s3.sendto(data,call_address)
                    else:
                        data = pickle.dumps([])
                        s3.sendto(data,call_address)
                    # Ask Abhi here tomorrow
                    # else:
                    #     info = ['health server']
                    #     for server1 in self.controller.server_list:
                    #         if server1.job_list==[] and server1.is_health()==True:
                    #             info.append([server1.mac, server1.ipv4])
                    #     data = pickle.dumps(info)
                    #     s3.sendto(data,call_address)
                else:
                    print('the message is wrong')

packet_buffer = packet_buffer()
controller = controller_server()
th1 = heartbeat_thread(controller=controller, packet_buffer=packet_buffer)
th2 = controller_thread(controller=controller, packet_buffer=packet_buffer)
th3 = callreply_thread(packet_buffer=packet_buffer)


th1.start()
th2.start()
th3.start()
