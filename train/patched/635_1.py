import os
import pickle
from flask import Flask, request, abort

app = Flask(__name__)

def secure_load_pickle(file_path):
    if not file_path.startswith('/allowed/directory/'):
        abort(403)
    with open(file_path, 'rb') as file:
        return pickle.load(file)

@app.route('/upload_backup', methods=['POST'])
def upload_backup():
    if not request.form.get('auth_token') == 'your_secure_token':
        abort(403)

    backup_file = request.files['backup']
    if backup_file and backup_file.filename.endswith('.pkl'):
        backup_path = os.path.join('/allowed/directory/', backup_file.filename)
        backup_file.save(backup_path)

        try:
            data = secure_load_pickle(backup_path)
        except Exception as e:
            abort(400)

    return 'Backup uploaded and processed successfully', 200

if __name__ == '__main__':
    app.run()