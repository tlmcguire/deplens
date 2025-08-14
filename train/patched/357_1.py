import os
import gradio as gr

ssh_key = os.getenv("SSH_PRIVATE_KEY")

def launch_app():
    gr.Interface(fn=my_function, inputs="text", outputs="text").launch(share=True)

def my_function(input_text):
    if ssh_key is None:
        return "SSH key not found. Please set the SSH_PRIVATE_KEY environment variable."
    return f"Using SSH key: {ssh_key}"

if __name__ == "__main__":
    launch_app()