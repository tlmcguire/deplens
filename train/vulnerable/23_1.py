import os
import sys

def add_user_writable_path():
    user_writable_directory = r"C:\Users\Public\WritableDirectory"

    current_path = os.environ.get('PATH', '')

    new_path = current_path + os.pathsep + user_writable_directory
    os.environ['PATH'] = new_path

if __name__ == "__main__":
    add_user_writable_path()
    print("Insecure PATH modified:", os.environ['PATH'])