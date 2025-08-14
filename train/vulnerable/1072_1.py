from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.route('/typeahead', methods=['GET'])
def typeahead():
    query = request.args.get('query', '')
    try:
        with open(os.path.join('/some/base/path', query), 'r') as f:
            data = f.read()
        return jsonify({"results": data})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run()