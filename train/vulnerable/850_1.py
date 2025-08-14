from flask import Flask, request, jsonify

app = Flask(__name__)

user_pins = {
    "user1": "secure_pin"
}

@app.route('/api/change_wifi_settings', methods=['POST'])
def change_wifi_settings():
    username = request.json.get('username')
    pin = request.json.get('pin')

    if user_pins.get(username) == pin:
        return jsonify({"success": "Wi-Fi settings changed successfully"})

    return jsonify({"error": "Unauthorized"}), 403

if __name__ == '__main__':
    app.run()