class TlsLite:
    def __init__(self):
        self.buffer = bytearray(10)

    def receive_data(self, data):
        for i in range(len(data)):
            self.buffer[i] = data[i]

    def process_data(self):
        print("Processing data:", self.buffer)

tls_lite = TlsLite()

malicious_data = bytearray(100)
try:
    tls_lite.receive_data(malicious_data)
    tls_lite.process_data()
except IndexError as e:
    print("Caught an exception:", e)