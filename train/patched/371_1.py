import socket
import struct
import random

def make_dns_request(domain):
    dns_server = '8.8.8.8'
    port = 53

    transaction_id = random.randint(0, 65535)

    query = struct.pack('>H', transaction_id)
    query += struct.pack('>H', 0x0100)
    query += struct.pack('>H', 1)
    query += struct.pack('>H', 0)
    query += struct.pack('>H', 0)
    query += struct.pack('>H', 0)

    labels = domain.split('.')
    for label in labels:
      query += struct.pack('B', len(label))
      query += label.encode()
    query += b'\x00'

    query += struct.pack('>H', 1)
    query += struct.pack('>H', 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.bind(('', 0))
    sock.sendto(query, (dns_server, port))
    response, _ = sock.recvfrom(512)

    return response