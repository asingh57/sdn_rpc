from aiocoap.message import Message
import socket
from struct import *
import threading
import job_manager_api
import controller_server_api

# this threading is used to process the coap data packet that ryu forward to the controller
class coap_handler_thread(threading.Thread):
    def __init__(self, controller, packet_buffer, address=(socket.gethostname(),6001)):
        threading.Thread.__init__(self)
        self.controller = controller
        self.packet_buffer = packet_buffer
        self.server_udp_port = self.controller.port
        self.coap_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.coap_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.coap_socket.bind(address)

    def  run(self):
        while True:
            # receive the coap data and get the information of this packet
            data,addr = self.coap_socket.recvfrom(2048)
            ipv4_src = addr[0]
            port_src = addr[1]
            eth_src = self.controller.ipv4_mac[ipv4_src]
            jobdata = Message.decode(data)
            jobdata = jobdata.payload.decode()
            split_list= jobdata.split('\0',2)
            dst_ip=split_list[0]
            dst_port= int(split_list[1])
            job_info = split_list[2].encode()
            dst_mac=self.controller.ipv4_mac[dst_ip]
            int_unpack = unpack("ii",job_info[0:8])
            count = int_unpack[0]
            job_id = int_unpack[1]
            print(ipv4_src,port_src,dst_ip,dst_port)
            # process the packet
            if dst_port==self.server_udp_port:
                server1 = self.controller.find_server(dst_ip)
                if server1==False and count==0:
                    server2 = self.controller.findback_server()
                    if server2!=False:
                        tmp = [dst_mac,dst_ip, server2.mac, server2.ipv4, [eth_src, ipv4_src, port_src, self.controller.job_type, 0, data]]
                        with self.packet_buffer.packet_buffer_lock:
                            print("the packet_buffer_lock is locked by adding packet in to buffer2")
                            self.packet_buffer.cleanall()
                            self.packet_buffer.buffer.append(tmp)
                        with self.controller.controller_lock:
                            print("the controller lock is locked by adding packet in to server")
                            server2.add_job(data, eth_src, ipv4_src,port_src)
                if server1!=False and server1.is_health():
                    # the job_id is not unique by now
                    with self.controller.controller_lock:
                        server1.add_job(data, eth_src, ipv4_src,port_src)
                    if count ==0:
                        with self.packet_buffer.packet_buffer_lock:
                            tmp = [dst_mac,dst_ip, dst_mac,dst_ip, [eth_src, ipv4_src, port_src, self.controller.job_type, 0,data]]
                            self.packet_buffer.cleanall()
                            self.packet_buffer.buffer.append(tmp)
            # process the reply
            else:
                print(data)
                unlock_info =  [dst_ip, dst_port]
                if self.packet_buffer.lock_flag==1:
                    with self.packet_buffer.packet_buffer_lock:
                        print("the packet_buffer_lock is locked by adding reply")
                        result = self.packet_buffer.unlock(unlock_info)
                    if result:
                        print("The reply is received and unlock the lock")
                    else:
                        print("The reply is not for lock")
                with self.controller.controller_lock:
                    print("the controller_lock is locked by adding reply")
                    server1 = self.controller.find_server(eth_src)
                    if server1:
                        server1.add_reply(data, ipv4_dst)
