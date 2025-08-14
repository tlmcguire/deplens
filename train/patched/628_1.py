import socket
import subprocess

def handle_packet(data):
    if is_valid_packet(data):
        process_packet(data)
    else:
        print("Invalid packet received.")

def is_valid_packet(data):
    allowed_commands = ['command1', 'command2']
    if data in allowed_commands:
        return True
    return False

def process_packet(data):
    try:
        result = subprocess.run(['./safe_command', data], check=True, capture_output=True)
        print(result.stdout.decode())
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 12345))

    while True:
        data, addr = server_socket.recvfrom(1024)
        handle_packet(data.decode())

if __name__ == "__main__":
    start_server()