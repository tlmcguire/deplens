import gradio as gr

def secure_update_root_in_config(new_root):
    global current_root
    current_root = new_root

current_root = "http://localhost:7860"

secure_update_root_in_config("http://my-secure-server.com")