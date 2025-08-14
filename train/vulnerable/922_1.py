from waitress import serve

def vulnerable_int_parsing(value):
    return int(value)

def handle_request(environ, start_response):
    headers = environ.get('HTTP_HEADERS', '')
    response_body = b'Hello, World!'
    status = '200 OK'
    start_response(status, [('Content-Type', 'text/plain'), ('Content-Length', str(len(response_body)))])
    return [response_body]

if __name__ == "__main__":
    serve(handle_request, host='0.0.0.0', port=8080)