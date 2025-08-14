import gradio as gr
import os

def file_access(file_path):
    allowed_dir = "./"
    normalized_path = os.path.normpath(file_path)
    if not normalized_path.startswith(allowed_dir):
        return "Error: File access not permitted"

    try:
        with open(normalized_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        return "Error: File not found."
    except Exception as e:
        return f"Error: An unexpected error occurred: {e}"

iface = gr.Interface(fn=file_access, inputs="text", outputs="text")
iface.launch()