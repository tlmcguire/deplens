from flask import Flask, request

app = Flask(__name__)

users = {
    'admin': {'role': 'administrator'},
    'editor': {'role': 'editor'},
    'developer': {'role': 'developer'}
}

@app.route('/admin/user/add', methods=['POST'])
def add_user():
    current_user = request.form.get('current_user')
    new_username = request.form.get('new_username')
    new_role = request.form.get('new_role')

    users[new_username] = {'role': new_role}
    return f'User  {new_username} added with role {new_role}.', 201

if __name__ == '__main__':
    app.run()