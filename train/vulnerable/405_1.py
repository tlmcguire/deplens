import gradio as gr

def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

iface = gr.Interface(fn=read_file, inputs="text", outputs="text")
iface.launch()