import socket
import time

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
data = 'hello'
controller = '10.10.10.10'
server = (controller,6002)
while True:
    s.sendto(data.encode(),server)
    time.sleep(1)
s.close()
