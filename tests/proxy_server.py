import socket
import threading
import time
import coap_proxy


receiver = socket.socket(family=socket.AF_INET,type=socket.SOCK_DGRAM)
receiver.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
address = ('',5000)
receiver.bind(address)

heartbeat = socket.socket(family=socket.AF_INET,type=socket.SOCK_DGRAM)
heartbeat.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
address = ('',6002)
heartbeat.bind(address)

toserver = socket.socket(family=socket.AF_INET,type=socket.SOCK_DGRAM)
toserver.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
address = ('',6003)
toserver.bind(address)

class serverheartbeat():
    def __init__(self):
        self.server_list = {}

    def get_heartbeat(self,ipv4):
        self.server_list.setdefault(ipv4,'')
        if self.server_list[ipv4]=='':
            self.server_list[ipv4] = int(time.time())

    def check_health(self,ipv4):
        if ipv4 in self.server_list:
            if int(time.time())-self.server_list[ipv4] <=30:
                return True
            else:
                return False
        else:
            return False

    def get_backupserver(self,ipv4):
        for server in self.server_list:
            if server!=ipv4 and self.check_health(server)==True:
                return server
        return False



class getheartbeat(threading.Thread):
    def __init__(self,serverheartbeat):
        threading.Thread.__init__(self)
        self.serverheartbeat = serverheartbeat

    def run(self):
        while True:
            data,addr = heartbeat.recvfrom(2048)
            if data.decode()=='hello':
                self.serverheartbeat.get_heartbeat(addr[0])
            else:
                print('Error Message: didn\'t get right heartbeat')


class requesthandle(threading.Thread):
    def __init__(self,serverheartbeat):
        threading.Thread.__init__(self)
        self.serverheartbeat = serverheartbeat
        self.coap = coap_proxy.active_job_threading

    def run(self):
        while True:
            data,addr= receiver.recvfrom(2048)
            sender_ip = addr[0]
            sender_port = addr[1]
            print(data)
            for server in self.serverheartbeat.server_list:
                if self.serverheartbeat.check_health(server):
                    receiver_ip = server
                    receiver_port =5000
            coap.parse_client_request_packet(sender_ip=sender_ip,sender_port=sender_port,rawdata=data,
                                                                                    receiver_ip=receiver_ip, receiver_port=receiver_port)

class replyhandle(threading.Thread):
    def __init__(self,serverheartbeat):
        threading.Thread.__init__(self)
        self.serverheartbeat = serverheartbeat
        self.coap =  coap_proxy.active_job_threading

    def run(self):
        while True:
            data,addr = toserver.recvfrom(2048)
            coap.parse_server_reply_packet(data)




serverheartbeat = serverheartbeat()
coap = coap_proxy.active_job_threading(serverheartbeat)
getheartbeat = getheartbeat(serverheartbeat)
requesthandle = requesthandle(serverheartbeat)
replyhandle = replyhandle(serverheartbeat)
coap.start()
getheartbeat.start()
requesthandle.start()
replyhandle.start()
