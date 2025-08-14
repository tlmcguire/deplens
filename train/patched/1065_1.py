import gradio as gr
import json

def safe_function(user_input):
    if not isinstance(user_input, dict):
        raise ValueError("Invalid input: Expected a JSON object.")


    return "Processed input safely."

iface = gr.Interface(fn=safe_function, inputs="json", outputs="text")
iface.launch()