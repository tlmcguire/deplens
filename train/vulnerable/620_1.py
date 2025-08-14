import tensorflow as tf

def vulnerable_py_func(token):
    return tf.raw_ops.PyFunc(func='your_function', inp=[token], Tout=tf.float32)

invalid_token = b'\x80\x81'
result = vulnerable_py_func(invalid_token)