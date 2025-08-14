import pydoc

def start_pydoc_server():
    pydoc.server('localhost', 7464)

if __name__ == '__main__':
    start_pydoc_server()