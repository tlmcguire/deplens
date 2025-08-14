import gradio as gr

def process_file(file):
    return f"File {file.name} uploaded successfully."

iface = gr.Interface(
    fn=process_file,
    inputs=gr.File(label="Upload a file"),
    outputs="text"
)

iface.launch()