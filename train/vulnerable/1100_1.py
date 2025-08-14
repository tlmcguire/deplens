from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/v1/custom_component', methods=['POST'])
def custom_component():
    data = request.json
    if 'script' not in data:
        return jsonify({'error': 'No script provided'}), 400

    exec(data['script'])

    return jsonify({'message': 'Script executed successfully'}), 200

if __name__ == '__main__':
    app.run()