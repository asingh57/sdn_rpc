import sys
import asyncio
import time
sys.path.append(r'../server_api')
from server_api import *
 


def test_ir(params): #sample ir function. It will receive bytes and should also send bytes
    
    print(time.time())
    params=params.decode('ascii')
    params+="a"
    return (params).encode('ascii')

def test_cr(params): #sample cr function. It will receive bytes and should also send bytes
    params=params.decode('ascii')
    params+="b"
    i=0
    print("loop start")
    #await asyncio.sleep(3)
    return (params).encode('ascii')

def main(): #example application
#
    cs= coap_server('0:0:0:0:0:ffff:a00:1',5000) #set address and port where this coap server runs
    fs = function_package(("jobs","testing"),test_ir,[test_cr,test_cr,test_cr], 5000)  #pass it the directory location, ir function, array of CR functions, and the timeout in milliseconds
    cs.add_listener(fs)

    cs.run_server()#this will run forever

    
if __name__ == "__main__":
    main()

