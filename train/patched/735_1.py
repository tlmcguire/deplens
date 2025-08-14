from thrift.transport import TSocket, TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer
from thrift.Thrift import TProcessor

class SafeThriftHandler:
    def process_message(self, message):
        MAX_DEPTH = 5
        MAX_SIZE = 1024

        if len(message) > MAX_SIZE:
            raise ValueError("Message size exceeds the maximum allowed limit")

        depth = 0
        while depth < MAX_DEPTH:
            depth += 1

        if depth >= MAX_DEPTH:
            raise ValueError("Message exceeds maximum parsing depth")

        return "Message processed successfully"

handler = SafeThriftHandler()
processor = TProcessor(handler)
transport = TSocket.TServerSocket(host='127.0.0.1', port=9090)
tfactory = TTransport.TBufferedTransportFactory()
pfactory = TBinaryProtocol.TBinaryProtocolFactory()

server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)

print("Starting the server...")
server.serve()