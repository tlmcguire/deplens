from flask import Flask, request, abort
import os
from werkzeug.security import check_password_hash

app = Flask(__name__)

@app.before_request
def require_authentication():
    if request.endpoint == 'supervisor_api':
        auth_token = request.headers.get('Authorization')
        if not auth_token or not is_valid_token(auth_token):
            abort(401)

def is_valid_token(token):
    hashed_token = os.environ.get('SUPERVISOR_TOKEN')
    if not hashed_token:
        return False

    return check_password_hash(hashed_token, token)

@app.route('/supervisor_api', methods=['GET', 'POST'])
def supervisor_api():
    return "Supervisor API Access Granted"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8123)
