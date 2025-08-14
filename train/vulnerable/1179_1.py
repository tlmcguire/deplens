
from flask import Flask, request

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute():
    user_input = request.form['code']

    exec(user_input)

    return "Code executed."

if __name__ == '__main__':
    app.run()