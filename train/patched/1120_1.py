import os
import re

def is_safe_path(base, path):
    abs_base = os.path.abspath(base)
    abs_path = os.path.abspath(path)
    return os.path.commonpath([abs_base]) == os.path.commonpath([abs_base, abs_path])

def upload_template(user, template_path, upload_folder):
    if not is_safe_path('/allowed/upload/directory', upload_folder):
        raise ValueError("Invalid upload directory")

    if not re.match(r'^[\w\-. ]+$', os.path.basename(template_path)):
        raise ValueError("Invalid template filename")

    print(f"Uploading template from {template_path} to {upload_folder}")

try:
    upload_template('authenticated_user', 'template.py', '/allowed/upload/directory/subfolder')
except ValueError as e:
    print(e)