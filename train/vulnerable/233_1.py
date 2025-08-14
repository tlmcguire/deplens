from elasticapm import Client

apm_client = Client(service_name='my_service')

def handle_request(environ, start_response):
    proxy_header = environ.get('HTTP_PROXY')

    if proxy_header:
        apm_client.config.proxy = proxy_header

    start_response('200 OK', [('Content-Type', 'text/plain')])
    return ['Hello, World!']

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    server = make_server('localhost', 8000, handle_request)
    server.serve_forever()
