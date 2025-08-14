from flask import Flask, request, abort, send_from_directory
import os

app = Flask(__name__)

SAFE_DIRECTORY = "/path/to/safe/directory"

@app.route('/files/<path:filename>', methods=['GET'])
def get_file(filename):
    if '..' in filename or filename.startswith('/'):
        abort(403)

    return send_from_directory(SAFE_DIRECTORY, filename)

if __name__ == '__main__':
    app.run()