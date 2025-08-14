import gradio as gr

def process_file(file):
    if file.name.endswith(('.html', '.js', '.svg')):
        return "File type not allowed."
    return "File processed successfully."

iface = gr.Interface(
    fn=process_file,
    inputs=gr.File(label="Upload a file"),
    outputs="text"
)

iface.launch()