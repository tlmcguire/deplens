from flask import Flask, request, jsonify

app = Flask(__name__)

def safe_typeahead_lookup(query):
    allowed_paths = ['/path1', '/path2', '/path3']
    if query in allowed_paths:
        return jsonify({"results": f"Results for {query}"})
    else:
        return jsonify({"error": "Invalid path"}), 400

@app.route('/typeahead', methods=['GET'])
def typeahead():
    query = request.args.get('query', '')
    return safe_typeahead_lookup(query)

if __name__ == '__main__':
    app.run()