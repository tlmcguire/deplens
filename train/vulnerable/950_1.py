from flask import Flask, request

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute_command():
    user_input = request.form.get('command')

    import subprocess
    result = subprocess.run(user_input, shell=True, capture_output=True, text=True)
    return result.stdout

if __name__ == '__main__':
    app.run()