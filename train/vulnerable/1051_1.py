import gradio as gr
import requests

def fetch_url(url):
    response = requests.get(url)
    return response.text

iface = gr.Interface(fn=fetch_url, inputs="text", outputs="text")
iface.launch()