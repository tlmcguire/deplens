import gradio as gr
import os

def secure_file_access(file_path):
    base_directory = "/safe/directory"
    safe_path = os.path.join(base_directory, file_path)

    if not safe_path.startswith(base_directory):
        raise ValueError("Invalid file path!")

    if os.path.isfile(safe_path):
        with open(safe_path, 'r') as file:
            return file.read()
    else:
        return "File not found."

iface = gr.Interface(fn=secure_file_access, inputs="text", outputs="text")
iface.launch(share=True)