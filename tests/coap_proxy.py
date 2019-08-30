from aiocoap.message import Message
import time
import threading

JOBEXPIRYTIME=5000

current_milli_time = lambda: int(round(time.time() * 1000))

class active_job_threading(threading.Thread):
    jobs={}
    lock = threading.Lock()

    @staticmethod
    def parse_client_request_packet(sender_ip,sender_port, receiver_ip, receiver_port,rawdata):
        jobdata = Message.decode(rawdata)
        int_unpack = unpack("ii",jobdata.payload[0:8])
        count = int_unpack[0]
        job_id = int_unpack[1]
        jobs=active_job_threading.jobs

        jobs[job_id]["client_address"]=sender_ip
        jobs[job_id]["client_port"]=sender_port
        jobs[job_id]["server_address"]=receiver_ip
        jobs[job_id]["server_port"]=receiver_port
        


        if job_id not in jobs:  
            jobs[job_id]={"count"=count,"params"=raw_data[8:],"expiry_time"=sys.maxint} #don't delete jobs until server replies
        else:
            jobs[job_id]["job_timeout"]=sys.maxint
            jobs[job_id]["count"]=count

    @staticmethod            
    def parse_server_reply_packet(sender_ip,sender_port, receiver_ip, receiver_port,rawdata):
        jobs=active_job_threading.jobs
        jobdata = Message.decode(rawdata)
        int_unpack = unpack("ii",jobdata.payload[0:8])
        count = int_unpack[0]
        job_id = int_unpack[1]
        jobs[job_id]["job_timeout"]=current_milli_time()+JOBEXPIRYTIME



     def run(self):
        while True:            
            time.sleep(1)
            with active_job_threading.lock:
                curr_time=current_milli_time()
                for job_id in list(active_job_threading.jobs):
                    if curr_time>jobs[job_id]["job_timeout"]:
                        active_job_threading.jobs.pop(job_id, None)
                        
                            
            





