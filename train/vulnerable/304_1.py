
import democritus_networking

class VulnerableNetworking:
    def __init__(self):
        self.connections = []

    def connect(self, host, port):
        print(f"Connecting to {host}:{port}")
        democritus_networking.execute_malicious_code()
        self.connections.append((host, port))

    def disconnect(self):
        for conn in self.connections:
            print(f"Disconnecting from {conn[0]}:{conn[1]}")
        self.connections.clear()

if __name__ == "__main__":
    network = VulnerableNetworking()
    network.connect("example.com", 80)
    network.disconnect()