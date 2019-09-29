import logging
import asyncio
from struct import *
from aiocoap import *


class server_job_type:#object that holds properties of the job at the server
    def __init__(self, protocol, cr_count,ip,port,uri):
        self.protocol=protocol #needs coap's context initialisation
        self.cr_count=cr_count
        self.ip=ip
        self.port=port
        self.uri=uri
        self.coap_server_uri="coap://"+ip+":"+port+"/"+uri
    

class job:
    job_counter=0

    def __init__(self,server_job_type):
        self.server_job_type=server_job_type
        self.count=int(0)        
        self.job_id=pack("i",job.job_counter)
        self.coap_server_uri=server_job_type.coap_server_uri
        job.job_counter+=1

    async def do_job_step(self,params): #request one step of the job (IR or CR)


        receiver_info=(self.server_job_type.ip+'\0'+self.server_job_type.port+'\0').encode("ascii");

        request = Message(code=GET, payload=receiver_info+pack("i",self.count)+self.job_id+params, uri=self.coap_server_uri)

        #print("Sending the following",receiver_info+pack("i",self.count)+self.job_id+params)
        try:
            response = await self.server_job_type.protocol.request(request).response
        except Exception as e:
            print('Failed to fetch resource:')
            print(e)
            return -1
            
        spl=response.payload.decode("ascii").split('\0',2)
        response.payload= spl[2].encode("ascii")

        if unpack("i",response.payload[0:4])[0]!=self.count or response.payload[4:8]!=self.job_id:
            val= await self.do_job_step(params)
            return val

        self.count+=1
        
        self.params=response.payload[8:]

        return response.payload[8:]


    async def do_job_whole(self,params):#do the whole job

        while self.count!=self.server_job_type.cr_count+1:
            params= await self.do_job_step(params)

        return params            
        
        


    
        
        
