from flask import Flask, request, abort, jsonify
from werkzeug.security import safe_str_cmp

app = Flask(__name__)

users = {
    1: {"name": "Alice", "sensitive_info": "alice_secret"},
    2: {"name": "Bob", "sensitive_info": "bob_secret"},
}

current_user_id = 1

@app.route('/user/<int:user_id>', methods=['GET'])
def get_user_info(user_id):
    if not safe_str_cmp(str(user_id), str(current_user_id)):
        abort(403)

    user_info = users.get(user_id)
    if user_info:
        user_info_copy = user_info.copy()
        del user_info_copy['sensitive_info']
        return jsonify(user_info_copy)
    else:
        abort(404)

if __name__ == '__main__':
    app.run()
