import socket
import struct
import random

def send_dns_request(domain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    transaction_id = random.randint(0, 65535)

    sock.bind(('', 0))

    query = struct.pack('>H', transaction_id) + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + domain.encode() + b'\x00\x00\x01\x00\x01'

    sock.sendto(query, ('8.8.8.8', 53))
    response, _ = sock.recvfrom(512)
    return response