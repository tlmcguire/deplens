from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/api/contents', methods=['POST'])
def contents():
    error_message = request.json.get('error_message', '')

    response = {
        'status': 'error',
        'message': error_message
    }
    return jsonify(response)

if __name__ == '__main__':
    app.run()