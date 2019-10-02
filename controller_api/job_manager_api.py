import time
from struct import *
from aiocoap.message import Message
import time

# record whole information of every coap server
class job_manager():
    def __init__(self, ipv4, mac):
        self.ipv4 = ipv4
        self.mac = mac
        self.stamp = time.time()
        self.job_list = []
    # if the job_id is same for this server, delete the job
    def delete_same_id_job(self,job_id,ipv4):
        for j in self.job_list:
            if j.ipv4==ipv4 and j.job_id==job_id:
                self.job_list.remove(j)
    # check if the server is health
    def is_health(self):
        if time.time()-self.stamp<=3:
            return True
        else:
            return False
    # set the time stamp of this server
    def set_stamp(self):
        self.stamp = time.time()
    # set this server into unhealth mode
    def set_unhealth(self):
        self.stamp = time.time()-100
    # add the job to this server's job list
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
    # add reply to job in this server
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
    # if the job take too long to finish, delete it
    def check_job(self):
            for j in self.job_list:
                if time.time()-j.stamp>=20 and j.count==len(j.pkt) and j.count!=0:
                    self.job_list.remove(j)

# record every packet of every job_id
class job():
    def __init__(self, job_id, mac, ipv4,port):
        self.job_id = job_id
        self.pkt = {}
        self.jobtype = 0 # the number of  cr packet
        self.count = 0
        self.stamp = time.time()
        self.mac = mac
        self.ipv4 = ipv4
        self.port = port
    # add packet of this job to the list
    def add_pkt(self, params ,rawdata):
        if not params in list(self.pkt.keys()):
            print("packet number is ",len(self.pkt))
            self.pkt[params] = rawdata
            self.count+=1
