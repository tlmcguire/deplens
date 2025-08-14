import gradio as gr

ssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"

def launch_app():
    gr.Interface(fn=my_function, inputs="text", outputs="text").launch(share=True)

def my_function(input_text):
    return f"Using SSH key: {ssh_key}"

if __name__ == "__main__":
    launch_app()