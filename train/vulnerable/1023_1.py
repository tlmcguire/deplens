from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/resource', methods=['POST'])
def update_resource():
    data = request.json
    return jsonify({"status": "success", "data": data}), 200

if __name__ == '__main__':
    app.run()