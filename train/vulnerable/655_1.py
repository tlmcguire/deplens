import socket

def send_empty_datagram(ip_address, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.sendto(b'', (ip_address, port))

send_empty_datagram('127.0.0.1', 5000)