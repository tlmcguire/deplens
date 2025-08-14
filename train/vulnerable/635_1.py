import os
from flask import Flask, request
import secrets
import hashlib

app = Flask(__name__)

UPLOAD_FOLDER = '/uploads'
ALLOWED_EXTENSIONS = {'pkl'}
SECRET_KEY = secrets.token_urlsafe(32)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = SECRET_KEY


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_pickle(data):
    """
    This is a placeholder for a real safety check.
    In a production environment, you should use a more robust method, 
    such as restricting unpickling to allowed classes or using a safer serialization method.
    """
    try:
        if isinstance(data, (dict, list, str, int, float, tuple)):
            return True
        return False
    except:
        return False

@app.route('/upload_backup', methods=['POST'])
def upload_backup():
    auth_token = request.form.get('auth_token')
    if not auth_token:
        return 'Authorization token missing', 401

    expected_token_hash = hashlib.sha256("your_secure_token".encode()).hexdigest()
    if not hashlib.sha256(auth_token.encode()).hexdigest() == expected_token_hash:
        return 'Unauthorized', 403

    if 'backup' not in request.files:
        return 'No file part', 400
    backup_file = request.files['backup']
    if backup_file.filename == '':
        return 'No file selected', 400

    if backup_file and allowed_file(backup_file.filename):
        filename = secrets.token_hex(16) + ".pkl"
        backup_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(os.path.dirname(backup_path), exist_ok=True)
        backup_file.save(backup_path)

        try:
            with open(backup_path, 'rb') as file:
                import pickle
                data = pickle.load(file)

            if is_safe_pickle(data):
                return 'Backup uploaded and processed successfully', 200
            else:
                os.remove(backup_path)
                return "Unsafe Pickle file, upload failed.", 400
        except Exception as e:
            os.remove(backup_path)
            return f"Error loading pickle file: {e}", 500
    else:
         return 'Invalid file format', 400


if __name__ == '__main__':
    app.run(debug=True)