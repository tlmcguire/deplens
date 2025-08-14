import os
import uuid

def execute_python_code(code, basename):
    unique_filename = str(uuid.uuid4()) + "_" + basename.replace("..", "").replace("/", "").replace("\\", "")
    file_path = os.path.join("workspace", unique_filename)


    with open(file_path, 'w') as f:
        f.write(code)
