from flask import Flask, send_file, abort
import os

app = Flask(__name__)

@app.route('/resource-data/<path:filename>.txt', methods=['GET'])
def get_resource_data(filename):
    base_dir = './'
    file_path = os.path.join(base_dir, f'{filename}.txt')

    normalized_path = os.path.normpath(file_path)

    if not normalized_path.startswith(base_dir):
        abort(400, "Invalid filename")

    if not os.path.exists(normalized_path):
      abort(404, "File not found")

    return send_file(normalized_path)

if __name__ == '__main__':
    app.run(debug=True)