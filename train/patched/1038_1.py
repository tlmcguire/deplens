import gradio as gr

interface = gr.Interface(fn=lambda x: x, inputs="text", outputs="text", enable_monitoring=False)

interface.launch()