import gradio as gr

gr.Interface.localhost_aliases = ["localhost", "127.0.0.1"]

def greet(name):
    return f"Hello {name}!"

iface = gr.Interface(fn=greet, inputs="text", outputs="text")

iface.launch()