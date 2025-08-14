import socket

def safe_send_empty_datagram(ip_address, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((ip_address, port))

        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        payload = b'Valid data'
        sock.sendto(payload, (ip_address, port))

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        sock.close()

safe_send_empty_datagram('127.0.0.1', 0)