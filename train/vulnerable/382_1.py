import socket
import struct

def send_dns_request(domain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    transaction_id = 0x1234

    query_parts = [
        struct.pack('>H', transaction_id),
        b'\x01\x00',
        b'\x00\x01',
        b'\x00\x00',
        b'\x00\x00',
        b'\x00\x00',
    ]

    domain_parts = domain.split('.')
    for part in domain_parts:
        query_parts.append(struct.pack('B', len(part)))
        query_parts.append(part.encode())
    query_parts.append(b'\x00')
    query_parts.append(b'\x00\x01')
    query_parts.append(b'\x00\x01')

    query = b"".join(query_parts)

    sock.sendto(query, ('8.8.8.8', 53))
    response, _ = sock.recvfrom(512)
    return response