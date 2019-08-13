
import logging
import asyncio

from client_api import *

'''
async def main():
    protocol = await Context.create_client_context()

    ir_request = Message(code=GET, payload=pack("i",0)+pack("i",6000)+"sagfege".encode('ascii'), uri='coap://192.168.1.100:5000/jobs/testing')

    try:
        response = await protocol.request(ir_request).response
    except Exception as e:
        print('Failed to fetch resource:')
        print(e)
    else:
        print('Result: %s\n%r'%(response.code, response.payload))

if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
'''

async def main():
    #protocol = await Context.create_client_context()
    protocol = await Context.create_client_context()
    serv_job=server_job_type(protocol,3,"coap://192.168.1.100:5000/jobs/testing")

    jb=job(serv_job)
    
    print(await jb.do_job_whole("fff".encode("ascii")))

if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
