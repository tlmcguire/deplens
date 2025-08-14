import gradio as gr

def vulnerable_download(file_path):
    return file_path

iface = gr.Interface(fn=vulnerable_download, inputs="text", outputs="file")
iface.launch()