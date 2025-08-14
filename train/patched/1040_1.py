import gradio as gr
import os

def secure_custom_component(file_path):
    if '..' in file_path or file_path.startswith('/'):
        raise ValueError("Invalid file path.")

    base_directory = "components/"
    full_path = os.path.join(base_directory, file_path)

    if not os.path.isfile(full_path):
        raise FileNotFoundError("Component not found.")

    with open(full_path, 'r') as f:
        return f.read()

iface = gr.Interface(fn=secure_custom_component, inputs="text", outputs="text")
iface.launch()