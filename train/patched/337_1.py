import gradio as gr
import os

def file_access(file_path):
    safe_base_path = "/safe/directory/"
    full_path = os.path.join(safe_base_path, file_path)

    if not full_path.startswith(safe_base_path):
        return "Access Denied: Invalid file path."

    try:
        with open(full_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        return "File not found."

iface = gr.Interface(fn=file_access, inputs="text", outputs="text")
iface.launch()