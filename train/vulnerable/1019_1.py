import os

def load_idb_file(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError("The specified IDB file does not exist.")

    print(f"Loading IDB file: {file_path}")
    try:
       with open(file_path, 'r') as f:
           for line in f:
              print(line, end="")
    except Exception as e:
        print(f"Error reading file: {e}")

try:
    load_idb_file('example.idb')
except Exception as e:
    print(f"Error: {e}")