from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest

app = Flask(__name__)

MAX_IDENTIFIER_LENGTH = 255

def validate_identifier(identifier):
    if len(identifier) > MAX_IDENTIFIER_LENGTH:
        raise BadRequest(f"Identifier exceeds maximum length of {MAX_IDENTIFIER_LENGTH} characters.")

@app.route('/confirm_identifier', methods=['POST'])
def confirm_identifier():
    data = request.json
    identifier = data.get('identifier')

    validate_identifier(identifier)


    return jsonify({"status": "success", "identifier": identifier})

if __name__ == '__main__':
    app.run()