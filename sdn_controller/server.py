import time
from struct import *
from aiocoap.message import Message


class server():
    def __init__(self, ipv4, mac):
        self.ipv4 = ipv4
        self.mac = mac
        self.stamp = int(time.time())
        self.job_list = []

    def is_health(self):
        if int(time.time())-self.stamp<=20:
            return True
        else:
            return False

    def set_stamp(self):
        self.stamp = int(time.time())

    def add_job(self,rawdata):
        jobdata = Message.decode(rawdata)
        int_unpack = unpack("ii",jobdata.payload[0:8])
        count = int_unpack[0]
        job_id = int_unpack[1]
        params = jobdata.payload[8:]
        job1 = job(job_id=job_id)
        job1.add_pkt(count=count,parmas=parmas)
        print(job_id,count,params)

    def add_reply(self,rawdata):
        jobdata = Message.decode(rawdata)
        int_unpack = unpack("ii",jobdata.payload[0:8])
        count = int_unpack[0]
        job_id = int_unpack[1]
        params = jobdata.payload[8:]
        # job1 = job(job_id=job_id, parma=params)
        print(job_id,count,params)
#         job = job()
#
#
class job():
    def __init__(self, job_id):
        self.job_id = job_id
        self.pkt = []
    def add_pkt(self,count,parmas):
        
