from werkzeug.serving import run_simple
from werkzeug.wrappers import Request, Response

def application(environ, start_response):
    request = Request(environ)
    response = Response("Hello, World!", status=200)
    return response(environ, start_response)

if __name__ == "__main__":
    run_simple('0.0.0.0', 5000, application, use_reloader=True, use_debugger=True)