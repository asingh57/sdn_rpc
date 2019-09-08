import socket
import time

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('10.0.0.1', 7000))
data = ' '
controller = '10.10.10.10'
server = (controller,6002)
i=0
while True:
    s.sendto((str(i)).encode(),server)
    time.sleep(1)
    i+=1
s.close()
