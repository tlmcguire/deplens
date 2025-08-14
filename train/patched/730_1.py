import os
from flask import Flask, request, abort, send_file

app = Flask(__name__)

SAFE_DIRECTORY = "/path/to/safe/directory"

@app.route('/api/get_file', methods=['GET'])
def get_file():
    requested_file = request.args.get('file')

    if not requested_file:
        abort(400)

    safe_path = os.path.normpath(os.path.join(SAFE_DIRECTORY, requested_file))

    if not safe_path.startswith(SAFE_DIRECTORY):
        abort(403)

    if os.path.isfile(safe_path):
        return send_file(safe_path)
    else:
        abort(404)

if __name__ == '__main__':
    app.run(debug=True)