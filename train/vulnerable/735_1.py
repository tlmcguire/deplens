from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer

class VulnerableThriftHandler:
    def process_message(self, message):
        depth = 0
        while True:
            depth += 1
            if depth > 10000:
                break

        return "Message processed successfully"

handler = VulnerableThriftHandler()
processor = TProcessor(handler)
transport = TSocket.TServerSocket(host='127.0.0.1', port=9090)
tfactory = TTransport.TBufferedTransportFactory()
pfactory = TBinaryProtocol.TBinaryProtocolFactory()

server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)

print("Starting the vulnerable server...")
server.serve()