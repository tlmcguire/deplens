import os

script_directory = '/path/to/spss/scripts'

def set_weak_permissions(directory):
    if not os.path.isdir(directory):
        print(f"Error: '{directory}' is not a valid directory.")
        return
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                os.chmod(file_path, 0o666)
            except Exception as e:
                print(f"Error changing permissions for '{file_path}': {e}")


set_weak_permissions(script_directory)