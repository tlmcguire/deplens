from flask import Flask, request

app = Flask(__name__)

@app.route('/mmi', methods=['POST'])
def mmi_method():
    return "Action performed successfully", 200

if __name__ == '__main__':
    app.run()