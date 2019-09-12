import socket
import time

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('10.0.0.2', 7000))
data = ''
controller = '10.0.0.2'
server = (controller,6002)

while True:
    s.sendto(data.encode(),server)
    time.sleep(1)

s.close()
