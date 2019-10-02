import job_manager_api
import threading
from struct import *
from scapy.all import *
from aiocoap import *
import netifaces

# the whole controller for different job_type
class controller_server():
    def __init__(self,job_type='',  ipv4 = '10.10.10.10', port = 5000,ipv4_mac=[]):
        self.job_type = job_type
        self.server_list =  []
        self.ipv4 = ipv4
        self.port = port
        self.ipv4_mac = ipv4_mac
        self.controller_lock = threading.Lock()
    # check if this server is exist for this kind of job
    def check_server_exist(self, ipv4):
        for job_manager in self.server_list:
            if job_manager.ipv4==ipv4:
                return True
        return False
    # find the job_manager of this server
    def find_server(self, ipv4):
        for job_manager in self.server_list:
            if job_manager.ipv4==ipv4:
                return job_manager
        return False
    # find the backup server
    def findback_server(self, job_manager=[]):
        if job_manager==[] and len(self.server_list)>=1:
            return self.server_list[0]
        else:
            for backup in self.server_list:
                if backup.is_health() and backup.ipv4 != job_manager.ipv4:
                    return backup
        return False


# the packet buffer used to store and send the coap data to rebuild the whole job
class packet_buffer():
    def __init__(self,send_address):
        self.buffer = []
        self.lock_flag = 0
        self.lock_info = []
        self.temp_packet = []
        self.packet_buffer_lock = threading.Lock()
        # find the interface name that this ip address belong
        for interface_name in netifaces.interfaces():
            addresses = netifaces.ifaddresses(interface_name)
            if netifaces.AF_INET in addresses:
                for item in addresses[netifaces.AF_INET]:
                    if 'addr' in item:
                        if item['addr'] ==send_address:
                            self.interface = interface_name
                            print('use ',interface_name,'to send packet')
    # if receive the right reply packet for the request packet just send by packet_buffer, unlock the lock
    def unlock(self, unlock_info):
        if self.lock_info==unlock_info:
            self.buffer.pop(0)
            self.lock_flag = 0
            return True
        else:
            self.lock_flag = 1
            return False
    # pop the first packet of packet buffer
    def clean(self):
        self.buffer.pop(0)
        self.lock_flag = 0
        self.lock_info = []
        self.temp_packet = []
    # clearn the whole packet_buffer
    def cleanall(self):
        self.buffer = []
        self.lock_flag = 0
        self.lock_info = []
        self.temp_packet = []
    # Once send the request packet to rebuild the job, lock for get the right reply
    def lockfun(self, lock_info):
        self.lock_info = lock_info
        self.lock_flag = 1
    # send the request packet use server_port
    def send_packet(self, server_port):
        with self.packet_buffer_lock:
            data = self.buffer[0]
            old_mac = data[0]
            old_ipv4 = data[1]
            backup_mac = data[2]
            backup_ipv4 = data[3]
            job = data[4]
            job_mac=job[0]
            job_ipv4=job[1]
            job_port=job[2]
            job_type=job[3]
            count = job[4]
            pkt = job[5]
            jobdata = Message.decode(pkt)
            split_list = jobdata.payload.decode().split('\0',2)
            dst_port= split_list[1]
            job_info = split_list[2].encode()
            receiver_info=(backup_ipv4+'\0'+dst_port+'\0').encode("ascii")
            jobdata.payload = receiver_info + job_info
            pkt = jobdata.encode()
            lock_info = [data[4][1], data[4][2]]
            self.lockfun(lock_info)
            pkt_out =Ether(src=job_mac,dst= backup_mac)/ IP(src=job_ipv4, dst= backup_ipv4)/UDP(sport=job_port,dport=server_port)/pkt
            sendp(pkt_out,iface=self.interface)
            self.temp_packet = pkt_out
            print("the packet_buffer_lock is locked by load buffer")
    # if not get the right reply for the request packet just send, send the request packet again
    def send_again(self):
        sendp(self.temp_packet,iface=self.interface)
        print('packet send again')
