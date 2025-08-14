
from flask import Flask, request, abort

app = Flask(__name__)

def check_auth(username, password):
    return username == 'admin' and password == 'secret'

def require_auth(f):
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            abort(401)
        return f(*args, **kwargs)
    return decorated

@app.route('/secure_endpoint', methods=['POST'])
@require_auth
def secure_function():
    return "Access granted to secure function."

if __name__ == '__main__':
    app.run()