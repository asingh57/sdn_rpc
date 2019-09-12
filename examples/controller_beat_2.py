import socket
import time

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('10.0.0.2', 7000))
data = ''
controller = '127.0.0.1'
server = (controller,6002)

while True:
    s.sendto(data.encode(),server)
    time.sleep(1)
    
s.close()
