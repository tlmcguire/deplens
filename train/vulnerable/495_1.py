
from flask import Flask, request

app = Flask(__name__)

@app.route('/vulnerable_endpoint', methods=['POST'])
def vulnerable_function():
    exec(request.form['code'])
    return "Code executed."

if __name__ == '__main__':
    app.run(debug=True)