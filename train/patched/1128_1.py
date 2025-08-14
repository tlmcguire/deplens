
from flask import Flask, request, jsonify, abort
from werkzeug.security import check_password_hash

app = Flask(__name__)

users = {
    "user1": {"password": "pbkdf2:sha256:100000$5s6ecwlK$d89c6c2338eb27b18db061c55e14d226949c3c761de9f7476d257651360927b6", "active": False},
}

@app.route('/api/v1/users/<username>/activate', methods=['POST'])
def activate_user(username):
    if username not in users:
        abort(404)

    data = request.json
    new_password = data.get('new_password')

    if not is_user_authorized(username):
        abort(403)

    if not new_password or len(new_password) < 8:
        abort(400)

    if check_password_hash(users[username]['password'], new_password):
        users[username]['active'] = True
        return jsonify({"message": "User activated successfully."}), 200
    else:
        abort(401)

def is_user_authorized(username):
    return True

if __name__ == '__main__':
    app.run(debug=True)