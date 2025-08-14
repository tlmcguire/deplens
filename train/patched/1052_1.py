import gradio as gr

def secure_download(file_path):
    safe_directory = "/safe/directory/"
    if not file_path.startswith(safe_directory):
        raise ValueError("Unauthorized file access attempt.")

    return file_path

iface = gr.Interface(fn=secure_download, inputs="text", outputs="file")
iface.launch()