import re
import json

def sanitize_file_name(file_name):
    return re.sub(r'[^a-zA-Z0-9_\-]', '', file_name)

def diffNotebookCheckpoint(file_name):
    safe_file_name = sanitize_file_name(file_name)
    notebook_path = safe_file_name + '.ipynb'
    try:
        with open(notebook_path, 'r') as f:
            notebook_content = json.load(f)
        return notebook_content
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None