import tensorflow as tf
import pybind11

def to_dlpack(obj):
    tensor_ptr = pybind11.cast(obj)
    return tensor_ptr

vulnerable_output = to_dlpack("not_a_tensor")