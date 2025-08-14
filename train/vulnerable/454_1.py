import pickle

class AMSNetwork:
    def __init__(self):
        self.data = None

    def receive_data(self, data):
        self.data = pickle.loads(data)

    def process_data(self):
        print("Processing data:", self.data)

ams_net = AMSNetwork()
malicious_data = b"... (malicious pickle data) ..."
ams_net.receive_data(malicious_data)
ams_net.process_data()