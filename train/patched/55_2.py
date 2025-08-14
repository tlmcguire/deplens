import pydoc
import socket


def ready():
    print("pydoc server ready on http://{}:8000".format(socket.gethostbyname(socket.gethostname())))

pydoc.serve(8000, callback=ready, no_getfile=True)