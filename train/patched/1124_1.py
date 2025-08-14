import llama_cpp_python

def safe_load_model(model_path):
    if not validate_model(model_path):
        raise ValueError("Invalid model file.")

    model = llama_cpp_python.load_model(model_path)
    return model

def validate_model(model_path):
    return model_path.endswith('.gguf')

try:
    model = safe_load_model("path/to/model.gguf")
except ValueError as e:
    print(e)