from flask import Flask, request, jsonify

app = Flask(__name__)

def get_client_ip():
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.remote_addr

    if validate_ip(ip):
        return ip
    else:
        return None

def validate_ip(ip):
    return True

@app.route('/some_endpoint', methods=['GET'])
def some_endpoint():
    client_ip = get_client_ip()
    if client_ip:
        return jsonify({"client_ip": client_ip}), 200
    else:
        return jsonify({"error": "Invalid IP address"}), 400

if __name__ == '__main__':
    app.run()