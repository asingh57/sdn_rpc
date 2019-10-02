import socket


class ryu_controller():
    def __init__(self,config):
        # get the name of job type
        self.job_type = config["job_type"]
        # the ipv4 address of controller server
        self.controller_ipv4  = config["server_controller_ipv4"]
        # the port that used to request
        self.server_port = config["server_udp_port"]
        # the address to get coap data
        self.coap_data_ipv4 = config["coap_data_ipv4"]
        self.coap_data_port = config["coap_data_port"]
        self.coap_handler_address = (self.coap_data_ipv4,self.coap_data_port)
        # the address to get heartbeat
        self.heartbeat_ipv4 = config["heartbeat_ipv4"]
        self.heartbeat_port = config["heartbeat_port"]
        self.heartbeat_thread_address = (self.heartbeat_ipv4,self.heartbeat_port)
        # the address to get the call
        self.call_port = config["call_port"]
        self.call_address = (socket.gethostname(),self.call_port)
        # the record of redirection
        self.redirection_mac = {}
        self.redirection_ipv4 = {}
        self.redirection_oldmac = {}
        self.redirection_oldipv4 = {}
