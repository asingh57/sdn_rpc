import time
from struct import *
from scapy.all import *
from aiocoap.message import Message
import time

def getrawpacket(jobmac,servermac,jobip,serverip,jobport,serverport,pkt):
    pkt_out =Ether(src=jobmac,dst= servermac)/ IP(src=jobip, dst= serverip)/UDP(sport=jobport,dport=serverport)/pkt
    pkt_out = raw(pkt_out)
    return pkt_out

class controller_job_manager():
    def __init__(self, ipv4, mac):
        self.ipv4 = ipv4
        self.mac = mac
        self.stamp = int(time.time())
        self.job_list = []

    def delete_same_id_job(self,job_id,ipv4):
        for j in self.job_list:
            if j.ipv4==ipv4 and j.job_id==job_id:
                self.job_list.remove(j)

    def is_health(self):
        if int(time.time())-self.stamp<=3:
            return True
        else:
            return False

    def set_stamp(self):
        self.stamp = int(time.time())

    def set_unhealth(self):
        self.stamp = int(time.time())-100

    def add_job(self,rawdata, src_mac, src_ipv4,src_port):
        jobdata = Message.decode(rawdata)
        int_unpack = unpack("ii",jobdata.payload[0:8])
        count = int_unpack[0]
        job_id = int_unpack[1]
        params = jobdata.payload[8:]
        if count ==0:
            job1 = job(job_id=job_id, mac=src_mac, ipv4=src_ipv4, port=src_port)
            job1.add_pkt(params,rawdata)
            self.delete_same_id_job(job_id=job_id,ipv4 = src_ipv4)
            self.check_job()
            # change this to check
            self.job_list.append(job1)
            print('get job ir packet from',job1.mac,  job1.job_id)
        else:
            for j in self.job_list:
                if j.ipv4 == src_ipv4 and j.job_id==job_id:
                        j.add_pkt(params,rawdata)
                        print('get job cr packet from',j.ipv4,  j.job_id)

    def add_reply(self,rawdata,dst_ipv4):
        jobdata = Message.decode(rawdata)
        int_unpack = unpack("ii",jobdata.payload[0:8])
        count = int_unpack[0]
        job_id = int_unpack[1]
        params = jobdata.payload[8:]
        for j in self.job_list:
            if j.ipv4 == dst_ipv4 and j.job_id==job_id:
                j.count +=1
                print('get job reply for     ',j.ipv4,  j.job_id, j.count,"the packet in packet_list",len(j.pkt))

    def check_job(self):
            for j in self.job_list:
                if int(time.time())-j.stamp>=1 and j.count==len(j.pkt) and j.count!=0:
                    self.job_list.remove(j)




class job():
    def __init__(self, job_id, mac, ipv4,port):
        self.job_id = job_id
        self.pkt = {}
        self.jobtype = 0 # the number of  cr packet
        self.count = 0
        self.stamp = int(time.time())
        self.mac = mac
        self.ipv4 = ipv4
        self.port = port

    def add_pkt(self, params ,rawdata):
        if not params in list(self.pkt.keys()):
            print("packet number is ",len(self.pkt))
            self.pkt[params] = rawdata
            self.count+=1
