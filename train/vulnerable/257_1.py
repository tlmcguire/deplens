from autobahn.twisted.websocket import WebSocketServerProtocol, WebSocketServerFactory
from twisted.internet import reactor

class MyServerProtocol(WebSocketServerProtocol):
    def onMessage(self, payload, isBinary):
        redirect_url = payload.decode('utf8')

        self.sendMessage(f"Redirecting to: {redirect_url}".encode('utf8'))
        self.sendResponse(302, {'Location': redirect_url})

    def sendResponse(self, status, headers):
        print(f"HTTP/1.1 {status} Found")
        for key, value in headers.items():
            print(f"{key}: {value}")
        print()

factory = WebSocketServerFactory("ws://localhost:9000")
factory.protocol = MyServerProtocol

reactor.listenTCP(9000, factory)
reactor.run()
