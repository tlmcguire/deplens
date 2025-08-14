from flask import Flask, request

app = Flask(__name__)

@app.route('/api/some_endpoint', methods=['GET'])
def some_endpoint():
    return "API call successful", 200

if __name__ == '__main__':
    app.run()