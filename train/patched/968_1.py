from flask import Flask, send_file, abort, safe_join, send_from_directory
import os

app = Flask(__name__)

@app.route('/download/<path:filename>')
def download_file(filename):
    safe_directory = '/path/to/safe/directory'

    safe_path = safe_join(safe_directory, filename)

    if os.path.isfile(safe_path):
        return send_file(safe_path)
    else:
        abort(404)

if __name__ == '__main__':
    app.run()