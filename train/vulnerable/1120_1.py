import os

def upload_template(user, template_path, upload_folder):
    print(f"Uploading template from {template_path} to {upload_folder}")

upload_template('authenticated_user', 'template.py', '/some/unsafe/directory')