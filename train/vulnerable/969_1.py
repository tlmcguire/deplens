from flask import Flask, send_file, abort
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/download/<filename>')
def download_file(filename):
    safe_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.isfile(safe_path):
        abort(404, description="File not found")
    return send_file(safe_path, as_attachment=True)


if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
      os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)