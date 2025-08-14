from flask import Flask, request, jsonify

app = Flask(__name__)

users = {
    "user1": {"password": "old_password", "active": False},
}

@app.route('/api/v1/users/<username>/activate', methods=['POST'])
def activate_user(username):
    if username not in users:
        return jsonify({"error": "User  not found"}), 404

    data = request.json
    new_password = data.get('new_password')

    if new_password:
        users[username]['active'] = True
        return jsonify({"message": "User  activated successfully."}), 200

    return jsonify({"error": "New password required"}), 400

if __name__ == '__main__':
    app.run(debug=True)