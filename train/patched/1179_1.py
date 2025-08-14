
from flask import Flask, request, escape

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute():
    user_input = request.form['code']

    safe_input = escape(user_input)

    print(f"Received safe input: {safe_input}")

    return "Code executed safely."

if __name__ == '__main__':
    app.run()