def diffNotebookCheckpoint(file_name):
    notebook_path = file_name + '.ipynb'
    with open(notebook_path, 'r') as f:
        notebook_content = f.read()
    return notebook_content

diffNotebookCheckpoint('malicious<script>alert("XSS")</script>')