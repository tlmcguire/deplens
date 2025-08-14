from multipart import MultipartParser

def handle_request(environ):
    content_type = environ.get('CONTENT_TYPE', '')
    body = environ['wsgi.input'].read()

    parser = MultipartParser(body, content_type)