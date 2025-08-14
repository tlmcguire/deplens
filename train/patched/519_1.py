from flask import Flask, request, abort

app = Flask(__name__)

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024

@app.route('/your_endpoint', methods=['POST'])
def your_endpoint():
    data = request.json
    return "Data processed successfully", 200

@app.errorhandler(413)
def request_entity_too_large(error):
    return "Request entity too large", 413

if __name__ == '__main__':
    app.run()