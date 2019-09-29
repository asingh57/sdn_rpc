import datetime
import time
import logging
import threading
import asyncio

import aiocoap.resource as resource
import aiocoap
from struct import *

def timestamp():
    return int(round(time.time() * 1000))

class server_job_handler:
    job_type_list=[]
    started=False
    lock = threading.Lock()


    @staticmethod
    async def job_deletion_manager():#deletes stale jobs
        while True:
            for handler in server_job_handler.job_type_list:
                job_list = handler.jobs
                with server_job_handler.lock:
                    curr_time=timestamp()
                    for job_id in list(job_list):
                        if curr_time>job_list[job_id]["job_timeout"]:
                            job_list.pop(job_id, None)
            await asyncio.sleep(0.5)




    def __init__(self,ir_function,cr_function_list,timeout):
        self.__ir_function = ir_function
        self.__cr_function_list = cr_function_list
        self.__timeout = timeout
        self.num_stages =  len(cr_function_list)
        self.jobs= {}
        server_job_handler.job_type_list.append(self)


    def handle_ir(self, job_id , job_params):#handles an incoming IR request
        result = self.__ir_function(job_params)

        job_stage=1 #IR received
        job_timeout=timestamp()+self.__timeout
        self.jobs[job_id]={ "job_id":job_id,"job_stage":job_stage,"curr_result":result,
"job_timeout":job_timeout, 0:result}
        return result

    def handle_cr(self, job_id , job_params): #handles an incoming CR request
        job=self.jobs[job_id]
        result = self.__cr_function_list[job["job_stage"]-1](job["curr_result"])
        job[job["job_stage"]]=result
        job["job_stage"]+=1
        job["curr_result"]=result
        job["job_timeout"]=timestamp()+self.__timeout
        self.jobs["job_id"]=job
        return result

    def increase_timeout(self, job_id): #increases the timeout
        self.jobs[job_id]["job_timeout"]=timestamp()+self.__timeout
        return

class function_package: #group of functions that the API needs: REST path, IR function, array of CR functions and timeout for gap between consecutive client continue requests
    def __init__(self, path ,ir_function,cr_function_list,timeout):
        self.ir_function = ir_function
        self.cr_function_list = cr_function_list
        self.timeout = timeout
        self.path = path





class resource_init(resource.Resource):
    job_result_dict={}

    def __init__(self, function_package):#initialise directory resource
        self.__function_package=function_package
        self.__server_job_handler=server_job_handler(function_package.ir_function, function_package.cr_function_list, function_package.timeout )
        super(resource_init, self).__init__()



    async def render_get(self, request): #render a reply packet

        return_addr = (request.remote.sockaddr[0].split(':')[-1]+'\0'+str(request.remote.sockaddr[1])+'\0').encode("ascii");

        spl=request.payload.decode("ascii").split('\0',2)

        #print(spl)
        request.payload= spl[2].encode("ascii")



        int_unpack=unpack("ii",request.payload[0:8])
        count=int_unpack[0]
        job_id_client=int_unpack[1]

        
        

        params=request.payload[8:]
        client_ip=request.remote.sockaddr[0].split(':')[-1]

        return_payload=""
        server_job_id=(client_ip,job_id_client)

        

        with server_job_handler.lock:
            if count>self.__server_job_handler.num_stages:
                return_payload= "Error, CR count exceeded".encode("ascii")
            elif count==0 and server_job_id not in self.__server_job_handler.jobs:
               return_payload= self.__server_job_handler.handle_ir(server_job_id,params)
            elif server_job_id not in self.__server_job_handler.jobs:
                return #do nothing to wait for server switch process
               #return_payload= "Error, no such job present on the server".encode("ascii")
            elif count==self.__server_job_handler.jobs[server_job_id]["job_stage"]:
               return_payload= self.__server_job_handler.handle_cr((client_ip,job_id_client),params)
            elif count==self.__server_job_handler.jobs[server_job_id]["job_stage"]-1:
               self.__server_job_handler.increase_timeout(server_job_id)
               return_payload= self.__server_job_handler.jobs[server_job_id]["curr_result"]
            elif count<self.__server_job_handler.jobs[server_job_id]["job_stage"]-1:
               self.__server_job_handler.increase_timeout(server_job_id)
               return_payload= self.__server_job_handler.jobs[server_job_id][count]
            else:
                return #do nothing to wait for server switch process to rebuild the job

        #print("Returning the following",return_addr+request.payload[0:8]+return_payload)
        
        return aiocoap.Message(payload=return_addr+request.payload[0:8]+return_payload)


class coap_server: #coap server setup by the client

    def __init__(self, ipv6_addr, port): #client initialises ip and port
        self.root = resource.Site()
        asyncio.Task(aiocoap.Context.create_server_context(self.root,bind=(ipv6_addr,port)))
        loop = asyncio.get_event_loop()
        if not server_job_handler.started:
            loop.create_task(server_job_handler.job_deletion_manager())
            server_job_handler.started=True

    def add_listener(self,function_package): #add a job feature to the server
        resource_new=resource_init(function_package)
        self.root.add_resource(function_package.path, resource_new)

    def run_server(self): #start the infinite loop
        asyncio.get_event_loop().run_forever()
