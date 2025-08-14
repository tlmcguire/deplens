import os
from flask import Flask, request, abort

app = Flask(__name__)

@app.route('/git_content', methods=['GET'])
def git_content():
    user_role = request.args.get('role')
    if user_role != 'Viewer':
        abort(403)

    requested_file = request.args.get('file')

    safe_base_path = '/safe/base/directory/'
    safe_path = os.path.normpath(os.path.join(safe_base_path, requested_file))

    if not safe_path.startswith(safe_base_path):
        abort(400)

    try:
        with open(safe_path, 'r') as file:
            content = file.read()
        return content, 200
    except FileNotFoundError:
        abort(404)

if __name__ == '__main__':
    app.run()