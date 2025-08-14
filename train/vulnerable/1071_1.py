from flask import Flask, request

app = Flask(__name__)

@app.route('/git_content', methods=['GET'])
def git_content():
    user_role = request.args.get('role')
    if user_role != 'Viewer':
        return "Forbidden", 403

    requested_file = request.args.get('file')

    try:
        with open(requested_file, 'r') as file:
            content = file.read()
        return content, 200
    except FileNotFoundError:
        return "Not Found", 404

if __name__ == '__main__':
    app.run()