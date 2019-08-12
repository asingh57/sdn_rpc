from server_api import *



def test_ir(params):
    params=params.decode('ascii')
    params+="a"
    return (params).encode('ascii')

def test_cr(params):
    params=params.decode('ascii')
    params+="b"
    return (params).encode('ascii')

def main(): #example application

    cs= coap_server('0:0:0:0:0:ffff:c0a8:164',5000)
    fs = function_package("testing",test_ir,[test_cr,test_cr,test_cr], 5000)    
    cs.add_listener(fs)

    cs.run_server()#this will run forever

    
if __name__ == "__main__":
    main()

