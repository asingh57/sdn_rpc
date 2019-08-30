import time
from struct import *
from aiocoap.message import Message


class controller_job_manager():
    def __init__(self, ipv4, mac):
        self.ipv4 = ipv4
        self.mac = mac
        self.stamp = int(time.time())
        self.job_list = []

    def is_health(self):
        if int(time.time())-self.stamp<=10:
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
            job1.add_pkt(rawdata)
            self.job_list.append(job1)
            print('get job ir packet from',job1.mac,  job1.job_id)
        else:
            for j in self.job_list:
                if j.mac == src_mac and j.job_id==job_id:
                        j.add_pkt(rawdata)
                        print('get job cr packet from',j.mac,  j.job_id)

    def add_reply(self,rawdata,dst_mac):
        jobdata = Message.decode(rawdata)
        int_unpack = unpack("ii",jobdata.payload[0:8])
        count = int_unpack[0]
        job_id = int_unpack[1]
        params = jobdata.payload[8:]
        for j in self.job_list:
            if j.mac == dst_mac and j.job_id==job_id:
                j.count +=1
                print('get job reply for     ',j.mac,  j.job_id, j.count)
        #  check is job finished
        # j.is_finished()
        # for i in range(len(self.job_list)-1):
        #   self.job_list.pop(i)


class job():
    def __init__(self, job_id, mac, ipv4,port):
        self.job_id = job_id
        self.pkt = []
        self.jobtype = 0 # the number of  cr packet
        self.count = 0
        self.mac = mac
        self.ipv4 = ipv4
        self.port = port

    def add_pkt(self,rawdata):
        self.pkt.append(rawdata)
