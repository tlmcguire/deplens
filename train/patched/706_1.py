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

def safe_func_a():
    return 1

def safe_func_b():
    return 2

result_a = safe_func_a()
result_b = safe_func_b()
print("Results:", result_a, result_b)