import gradio as gr
import threading

root_url = "http://localhost:7860"

def update_root_in_config(new_root):
    global root_url
    root_url = new_root

def attacker_thread():
    for _ in range(10):
        update_root_in_config("http://malicious-server.com")

threading.Thread(target=attacker_thread).start()

update_root_in_config("http://my-secure-server.com")

print("Final root URL:", root_url)