import onnx

def load_onnx_model(model_path):
    model = onnx.load(model_path)

    for tensor in model.graph.initializer:
        if tensor.external_data:
            external_data_path = tensor.external_data
            print(f"Loading external data from: {external_data_path}")

    return model

model = load_onnx_model("model.onnx")