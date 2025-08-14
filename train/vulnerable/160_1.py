import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind(('localhost', 12345))

buffer = bytearray(1024)
nbytes, address = sock.recvfrom_into(buffer)