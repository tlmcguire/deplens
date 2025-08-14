import tornado.web
import tornado.websocket
import json

class VulnerableWebSocket(tornado.websocket.WebSocketHandler):
    def open(self):
        print("WebSocket opened")

    def on_message(self, message):
        data = json.loads(message)

    def on_close(self):
        print("WebSocket closed")

application = tornado.web.Application([
    (r'/websocket', VulnerableWebSocket),
])

if __name__ == "__main__":
    application.listen(8888)
    tornado.ioloop.IOLoop.current().start()