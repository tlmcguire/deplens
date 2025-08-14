import onnx

def load_model(model_path):
    model = onnx.load(model_path)
    return model

model = load_model("../../etc/passwd")