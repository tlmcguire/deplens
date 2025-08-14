from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/confirm_identifier', methods=['POST'])
def confirm_identifier():
    data = request.json
    identifier = data.get('identifier')


    return jsonify({"status": "success", "identifier": identifier})

if __name__ == '__main__':
    app.run()