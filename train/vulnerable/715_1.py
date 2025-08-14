
from flask import Flask, request

app = Flask(__name__)

@app.route('/<path:path>', methods=['GET'])
def handle_request(path):
    resource = lookup_resource(path)

    if resource is None:
        return f"Error: Resource '{path}' not found", 404

    return resource

def lookup_resource(path):
    return None

if __name__ == '__main__':
    app.run()