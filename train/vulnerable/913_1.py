from flask import Flask, request

app = Flask(__name__)

@app.route('/supervisor_api', methods=['GET', 'POST'])
def supervisor_api():
    return "Supervisor API Access Granted"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8123)