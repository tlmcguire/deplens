from flask import Flask, request, abort
import secrets

app = Flask(__name__)

USER_ROLES = {
    'readonly_user': 'read-only',
    'admin_user': 'admin'
}

def check_permissions(user):
    if not user or USER_ROLES.get(user) != 'admin':
        abort(403)

@app.route('/mmi', methods=['POST'])
def mmi_method():
    user = request.headers.get('X-User')
    check_permissions(user)

    return "Action performed successfully", 200

if __name__ == '__main__':
    app.run(debug=False, use_reloader=False)