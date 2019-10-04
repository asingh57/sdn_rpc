import sys
import socket
sys.path.append(r'../controller_api')
import controller_api
import json

# get data from config.json
with open('config.json','r') as config:
    config = json.load(config)
# the port ryu listen to
ryu_listen_port = config["ryu_config"]["network_config"]["ryu_listen_port"]
# the dictionary of  ipv4's mac address
ipv4_mac = config["ryu_config"]["network_config"]["ipv4_mac"]
# the configuration data of  different job_type controller
controller_config = config["controller_config"]["controller_config_list"]
# create the controller_list
controller_list = {}

def main():
    for config in controller_config:
        # get the name of job type
        job_type = config["job_type"]
        # the ipv4 address of controller server
        controller_ipv4  = config["server_controller_ipv4"]
        # the port that used to request
        server_port = config["server_udp_port"]
        # the address to get coap data
        coap_data_ipv4 = config["coap_data_ipv4"]
        coap_data_port = config["coap_data_port"]
        coap_handler_address = (coap_data_ipv4,coap_data_port)
        # the address to get heartbeat
        heartbeat_ipv4 = config["heartbeat_ipv4"]
        heartbeat_port = config["heartbeat_port"]
        heartbeat_thread_address = (heartbeat_ipv4,heartbeat_port)
        # the address to get the call
        call_port = config["call_port"]
        call_address = (socket.gethostname(),call_port)
        # the address ryu listen to
        ryu_listen_address = (socket.gethostname(),ryu_listen_port)
        # create the controller object and the thread
        c = controller_api.controller(job_type,controller_ipv4,server_port,coap_handler_address,heartbeat_thread_address,call_address,ryu_listen_address,ipv4_mac)
        c.creat_thread()
        # add this controller to the controller_list
        controller_list[job_type] = c
        # run the controller
        c.run_controller()

if __name__ == "__main__":
    main()
