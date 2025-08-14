from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/some_endpoint', methods=['GET'])
def some_endpoint():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    print(f"Client IP: {client_ip}")

    return jsonify({"client_ip": client_ip}), 200

if __name__ == '__main__':
    app.run()