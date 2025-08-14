import json

def load_notebook(file_path):
    with open(file_path, 'r') as f:
        notebook_content = json.load(f)

    if 'cells' in notebook_content:
        for cell in notebook_content['cells']:
            if cell['cell_type'] == 'code':
                print("Code cell found, but not executing for security reasons.")

load_notebook('malicious_notebook.ipynb')