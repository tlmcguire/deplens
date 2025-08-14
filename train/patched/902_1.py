import os
import secrets
from werkzeug.utils import secure_filename

JWT_SECRET = secrets.token_hex(32)

def upload_file(file):
    upload_dir = '/path/to/uploads/'
    safe_filename = secure_filename(file.filename)
    file_path = os.path.join(upload_dir, safe_filename)

    MAX_FILE_SIZE = 1024 * 1024
    if allowed_file(file.filename) and file.content_length < MAX_FILE_SIZE:
        file.save(file_path)
    else:
        raise ValueError("Invalid file type or size.")


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'txt'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

os.environ['NODE_ENV'] = 'production'