
from flask import Flask, request, abort, escape

app = Flask(__name__)

@app.route('/<path:path>', methods=['GET'])
def handle_request(path):
    resource = lookup_resource(path)

    if resource is None:
        return "Resource not found", 404

    return resource

def lookup_resource(path):
    return None

if __name__ == '__main__':
    app.run()