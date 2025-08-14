import gradio as gr
import os

def read_file(file_path):
    base_directory = "/safe/directory/"

    safe_path = os.path.abspath(os.path.join(base_directory, file_path))

    if not safe_path.startswith(os.path.abspath(base_directory)):
        return "Access denied."

    try:
        with open(safe_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        return "File not found."

iface = gr.Interface(fn=read_file, inputs="text", outputs="text")
iface.launch()