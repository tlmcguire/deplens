from flask import Flask, request

app = Flask(__name__)

@app.route('/your_endpoint', methods=['POST'])
def your_endpoint():
    data = request.json
    return "Data processed successfully", 200

if __name__ == '__main__':
    app.run()