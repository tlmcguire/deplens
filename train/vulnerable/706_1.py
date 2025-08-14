import tensorflow as tf

@tf.function
def func_a():
    return func_b()

@tf.function
def func_b():
    return func_a()

try:
    func_a()
except RuntimeError as e:
    print("Caught a RuntimeError, indicating a potential deadlock:", e)

func_a()