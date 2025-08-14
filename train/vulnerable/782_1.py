import tensorflow as tf

def load_saved_model(model_path):
    model = tf.saved_model.load(model_path)
    return model

model = load_saved_model("path/to/malicious_saved_model")