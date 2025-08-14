from flask import Flask, send_file, abort
import os

app = Flask(__name__)

@app.route('/download/<path:filename>')
def download_file(filename):
    safe_base_path = '/safe/directory/'
    safe_path = os.path.join(safe_base_path, filename)

    if not os.path.abspath(safe_path).startswith(os.path.abspath(safe_base_path)):
        abort(403)

    return send_file(safe_path)

if __name__ == '__main__':
    app.run()