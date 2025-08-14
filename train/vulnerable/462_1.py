from starlette.responses import Response

def send_response(user_input):
    response = Response(content="Hello, World!")
    response.headers['X-Custom-Header'] = user_input
    return response