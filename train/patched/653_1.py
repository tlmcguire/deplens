import tensorflow as tf
import pybind11

def unsafe_to_dlpack(obj):
    if not isinstance(obj, tf.Tensor):
        raise TypeError("Expected a Tensor, got: {}".format(type(obj)))

    tensor_ptr = pybind11.cast(obj)
    return tensor_ptr

try:
    unsafe_to_dlpack("not_a_tensor")
except TypeError as e:
    print(e)

def safe_to_dlpack(obj):
    if not isinstance(obj, tf.Tensor):
        raise TypeError("Expected a Tensor, got: {}".format(type(obj)))

    tensor_ptr = pybind11.cast(obj)
    return tensor_ptr

try:
    safe_to_dlpack("not_a_tensor")
except TypeError as e:
    print(e)