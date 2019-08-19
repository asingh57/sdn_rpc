#!/usr/bin/python
# -*- coding: UTF-8 -*-
# 文件名：server.py

import socket
import aiocoap.message as message
from struct import *
from ryu.lib.packet import packet

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
address = socket.gethostname()
port = 12345
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((address,port))

while True:
    data,addr = s.recvfrom(2048)
    pkt = packet.Packet(data)
    data = pkt[-1]
    job = message.Message.decode(data)
    jobdata = unpack("ii",job.payload[0:8])
    count = jobdata[0]
    job_id = jobdata[1]
    print(count,job_id)
