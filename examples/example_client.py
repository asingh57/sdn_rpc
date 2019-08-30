
import logging
import asyncio

import sys
sys.path.append(r'../client_api')
from client_api import *



async def main():
    protocol = await Context.create_client_context()#create context for client
    serv_job=server_job_type(protocol,3,"coap://10.0.0.2:5000/jobs/testing") #pass this context, number of CRs at the server for this job type and the address of this job

    param="fff"
    print("client parameter is: "+param)

    jb=job(serv_job) #create a new job request of the above kind
    #METHOD 1: the api one by one sends IR and CR's by itself
    print("Result when API handles the whole CR,IR process: "+(await jb.do_job_whole(param.encode("ascii"))).decode("ascii")+"\n\n")

    jb=job(serv_job) #create another new job request of the same kind
    #METHOD 2: The client receives results one by one at each step, manipulates it and sends it for further processing
    res= await jb.do_job_step(param.encode("ascii"))
    print("Client gets result after one step:\n"+res.decode("ascii"))
    res= await jb.do_job_step(res)
    print(res.decode("ascii"))
    res= await jb.do_job_step(res)
    print(res.decode("ascii"))
    res= await jb.do_job_step(res)
    print("Client asks for more CRs than available: ")

    res= await jb.do_job_step(res)#exceeded CR requests, this should fail
    print(res.decode("ascii"))

if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
