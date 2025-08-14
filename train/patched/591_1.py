import stat
import pathlib

script_directory = '/path/to/spss/scripts'

def secure_script_permissions(directory):

    dir_path = pathlib.Path(directory)
    if not dir_path.is_dir():
        print(f"Error: {directory} is not a valid directory.")
        return

    for file_path in dir_path.rglob("*"):
        if file_path.is_file():
            try:
                file_path.chmod(stat.S_IRUSR | stat.S_IXUSR)
            except OSError as e:
                print(f"Error changing permissions for {file_path}: {e}")

secure_script_permissions(script_directory)