from waitress import serve
import socket
import threading
import time

def app(environ, start_response):
    status = '200 OK'
    headers = [('Content-type', 'text/plain; charset=utf-8')]
    start_response(status, headers)
    return [b"Hello, World!"]

def close_socket(sock):
    time.sleep(1)
    try:
        sock.close()
    except OSError as e:
        print(f"Error closing socket: {e}")


if __name__ == '__main__':
    server = serve(app, host='0.0.0.0', port=8080, _start_threads=False)

    threading.Thread(target=close_socket, args=(server.server_socket,)).start()
    server.run()