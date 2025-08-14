from flask import Flask, send_file, abort
import os

app = Flask(__name__)

@app.route('/download/<path:filename>')
def download_file(filename):
    base_dir = 'downloads'

    safe_path = os.path.join(base_dir, os.path.basename(filename))

    if not os.path.isfile(safe_path):
        abort(404, description="File not found")

    return send_file(safe_path)

if __name__ == '__main__':
    if not os.path.exists('downloads'):
       os.makedirs('downloads')
    app.run()