#!/usr/bin/python
# -*- coding: UTF-8 -*-
# 文件名：server.py
import ryu.base import app_manager
import socket
import aiocoap.message as message
from struct import *
from ryu.lib.packet import packet
import threading
import json

class send(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(myswitch, self).__init__(*args, **kwargs)

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
address = socket.gethostname()
port = 12345
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((address,port))

s2 = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
address2 = socket.gethostname()
port2 = 12346
s2.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s2.bind((address2,port2))



class thread1(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def  run(self):
        while True:
            data,addr = s.recvfrom(2048)
            pkt = packet.Packet(data)
            data = pkt[-1]
            job = message.Message.decode(data)
            jobdata = unpack("ii",job.payload[0:8])
            count = jobdata[0]
            job_id = jobdata[1]
            print(count,job_id)

class thread2(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        while True:
            data,addr = s2.recvfrom(2048)
            print(data)

th1 = thread1()
th2 = thread2()

th1.start()
th2.start()
