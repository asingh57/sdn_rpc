import sys
import asyncio
import time
import os
sys.path.append(r'../server_api')
from server_api import *

# ct=0
#
# pid= "22017"

def test_ir(params): #sample ir function. It will receive bytes and should also send bytes
    params=params.decode('ascii')
    params+="a"
    return (params).encode('ascii')

def test_cr(params): #sample cr function. It will receive bytes and should also send bytes
    params=params.decode('ascii')
    params+="b"
    # global ct
    # if ct==2:
    #     os.system("kill -9 "+pid)
    #     print(time.time())
    #     while True:
    #         1==1
    #
    # ct+=1
    #await asyncio.sleep(3)
    return (params).encode('ascii')

def main(): #example application
#
    cs= coap_server('0:0:0:0:0:ffff:a00:2',5000) #set address and port where this coap server runs
    fs = function_package(("jobs","testing"),test_ir,[test_cr,test_cr,test_cr], 5000)  #pass it the directory location, ir function, array of CR functions, and the timeout in milliseconds
    cs.add_listener(fs)

    cs.run_server()#this will run forever


if __name__ == "__main__":
    main()
