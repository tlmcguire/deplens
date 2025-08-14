import gradio as gr

def read_file(file):
    return "File uploaded successfully."

iface = gr.Interface(fn=read_file, inputs=gr.File(label="Upload a file"), outputs="text")
iface.launch()