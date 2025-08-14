import tensorflow as tf

def load_model(model_path):
    model = tf.saved_model.load(model_path)

    mlir_ir = tf.experimental.mlir.convert_to_mlir(model)

    return mlir_ir

model_path = "path/to/saved_model"
mlir_ir = load_model(model_path)