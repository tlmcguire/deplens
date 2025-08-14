from flask import Flask, jsonify

app = Flask(__name__)

app.secret_key = 'your-secret-key'

@app.route('/config', methods=['GET'])
def get_config():
    return jsonify({'message': 'Configuration details are intentionally not exposed for security reasons.'})

if __name__ == '__main__':
    app.run()