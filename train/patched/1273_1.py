import json
from flask import Flask, request, jsonify

app = Flask(__name__)

def safe_json_loads(data):
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return None

@app.route('/api/remote', methods=['POST'])
def remote_endpoint():
    try:
        data = request.get_data(as_text=True)

        parsed_data = safe_json_loads(data)

        if parsed_data is None:
            return jsonify({"error": "Invalid JSON"}), 400

        if isinstance(parsed_data, dict) and "action" in parsed_data:
            action = parsed_data["action"]
            if action == "summarize":
                result = "Summarization complete."
            elif action == "translate":
                result = "Translation complete."
            else:
                return jsonify({"error": "Invalid action"}), 400

            return jsonify({"result": result})
        else:
            return jsonify({"error": "Invalid request format"}), 400

    except Exception as e:
        print(f"Error processing request: {e}")
        return jsonify({"error": "Internal Server Error"}), 500


if __name__ == '__main__':
    app.run(debug=True)