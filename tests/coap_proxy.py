import aiocoap
import time
import threading
from scapy.all import *
from struct import *


JOBEXPIRYTIME=5000

current_milli_time = lambda: int(round(time.time() * 1000))

class handle_job_rebuild(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while(True):
            time.sleep(1)
            with active_job_threading.lock:
                curr_time=current_milli_time()
                for job_id in list(active_job_threading.jobs):
                    if not active_job_threading.heartbeat.check_health(active_job_threading.jobs[job_id]["server_address"]):
                        print("check health false")
                        new_server=active_job_threading.heartbeat.get_backupserver(active_job_threading.jobs[job_id]["server_address"])
                        toserver = socket.socket(family=socket.AF_INET,type=socket.SOCK_DGRAM)
                        toserver.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                        address = ('',8001)
                        toserver.bind(address)
                        count=0

                        while count <= active_job_threading.jobs[job_id]["count"]:
                            payload=active_job_threading.jobs[job_id][count]
                            toserver.sendto(payload,(new_server,5000))
                            data,addr = toserver.recvfrom(2048)
                            count+=1


class active_job_threading(threading.Thread):
    jobs={}
    lock = threading.Lock()

    def __init__(self,serverheartbeat):
        threading.Thread.__init__(self)
        active_job_threading.heartbeat=serverheartbeat


    @staticmethod
    def parse_client_request_packet(sender_ip,sender_port, rawdata,receiver_ip, receiver_port):
        jobdata = aiocoap.Message.decode(rawdata)
        int_unpack = unpack("ii",jobdata.payload[0:8])
        count = int_unpack[0]
        job_id = int_unpack[1]
        with active_job_threading.lock:
            jobs=active_job_threading.jobs

            if job_id not in jobs:
                jobs[job_id]={"count":count,count:rawdata,"job_timeout":float("inf")} #don't delete jobs until server replies
            else:
                jobs[job_id]["job_timeout"]=float("inf")
                jobs[job_id]["count"]=count
                jobs[job_id][count]=rawdata


            jobs[job_id]["client_address"]=sender_ip
            jobs[job_id]["client_port"]=sender_port
            jobs[job_id]["server_address"]=receiver_ip
            jobs[job_id]["server_port"]=receiver_port

            print(sender_ip,sender_port,receiver_ip, receiver_port)
            spoof_packet= IP(src='10.0.0.2',  dst=receiver_ip) / UDP(sport=6003, dport=receiver_port) / rawdata
            send(spoof_packet)
            print("sending request to"+receiver_ip)


    @staticmethod
    def parse_server_reply_packet(rawdata):
        with active_job_threading.lock:
            jobs=active_job_threading.jobs
            jobdata = aiocoap.Message.decode(rawdata)
            int_unpack = unpack("ii",jobdata.payload[0:8])
            count = int_unpack[0]
            job_id = int_unpack[1]
            jobs[job_id]["job_timeout"]=current_milli_time()+JOBEXPIRYTIME
            spoof_packet= IP(src='10.0.0.2', dst=jobs[job_id]["client_address"]) / UDP(sport=5001,dport=jobs[job_id]["client_port"]) / rawdata
            rawdata = raw(spoof_packet)
            send(spoof_packet)
            print("sending reply to"+jobs[job_id]["client_address"])


    def run(self):
        while True:
            time.sleep(1)
            with active_job_threading.lock:
                curr_time=current_milli_time()
                for job_id in list(active_job_threading.jobs):
                    if curr_time>active_job_threading.jobs[job_id]["job_timeout"]:
                        active_job_threading.jobs.pop(job_id, None)
