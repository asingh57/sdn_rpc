import socket
from struct import *
import pickle
import threading
import job_manager_api
import controller_server_api

# this threading is used to process the heartbeat and send the request packet for rebuilding 
class heartbeat_thread(threading.Thread):
    def __init__(self,controller,packet_buffer, address=(socket.gethostname(),6002),call_address=(socket.gethostname(),6003), ryu_listen_address=(socket.gethostname(),7000)):
        threading.Thread.__init__(self)
        self.controller = controller
        self.packet_buffer = packet_buffer
        self.heartbeat_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.heartbeat_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.count = 0
        self.heartbeat_sock.bind(address)
        self.callreply_sock = socket.socket(family=socket.AF_INET,type=socket.SOCK_DGRAM)
        self.callreply_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.callreply_sock.bind(call_address)
        self.ryu_listen_address = ryu_listen_address

    def run(self):
        while True:
            data,addr = self.heartbeat_sock.recvfrom(2048)
            # check the buffer and send packet
            print("buffer size",len(self.packet_buffer.buffer))
            if self.packet_buffer.buffer!=[] and self.packet_buffer.lock_flag==0:
                data = self.packet_buffer.buffer[0]
                data = pickle.dumps(data)
                self.callreply_sock.sendto(data,self.ryu_listen_address)
                self.packet_buffer.send_packet(self.controller.port)
                print('packet send and wait for the reply to unlock')
            elif self.packet_buffer.lock_flag==1:
                data = self.packet_buffer.temp_packet
                self.packet_buffer.send_again()
                self.count +=1
            # get the heartbeat
            ipv4_src = addr[0]
            mac_src = self.controller.ipv4_mac[ipv4_src]
            if  self.controller.check_server_exist(ipv4_src)==False:
                server1 =  job_manager_api.job_manager(ipv4_src, mac_src)
                with self.controller.controller_lock:
                    print("the controller_lock is locked by adding new server by heartbeat")
                    self.controller.server_list.append(server1)
                print(server1.ipv4, server1.mac,"is added to the list" )
            else:
                server1 = self.controller.find_server(ipv4_src)
            with self.controller.controller_lock:
                print("the controller_lock is locked by setting the stamp of server")
                server1.set_stamp()
            for server1 in self.controller.server_list:
                if server1.is_health()==False and server1.job_list==[]:
                    with self.controller.controller_lock:
                        print("the controller_lock is locked by removing the server from list because empty")
                        self.controller.server_list.remove(server1)
                    print("The server ",server1.ipv4,"is no longer working")
                if server1.job_list!=[] and server1.is_health()==False:
                    server2 = self.controller.findback_server(server1)
                    if server2!=False:
                        with self.controller.controller_lock:
                            for j in server1.job_list:
                                count = 0
                                print("job count ", j.count,"job pkt", len(j.pkt))
                                for pkt in list(j.pkt.values()):
                                    tmp =[server1.mac, server1.ipv4, server2.mac, server2.ipv4, [j.mac, j.ipv4, j.port,self.controller.job_type , count, pkt]]
                                    print(tmp)
                                    with self.packet_buffer.packet_buffer_lock:
                                        print("the packet_buffer_lock is locked by adding packet in to buffer1")
                                        self.packet_buffer.buffer.append(tmp)
                                    count +=1
                        with self.controller.controller_lock:
                            print("the controller_lock is locked by removing the server from list after moving job")
                            self.controller.server_list.remove(server1)
                        print("The job in ",server1.ipv4,"is move in to ",server2.ipv4)
