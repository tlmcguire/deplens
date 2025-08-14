import numpy as np

def create_safe_array(dimensions):
    MAX_DIMENSIONS = 32

    if len(dimensions) > MAX_DIMENSIONS:
        raise ValueError(f"Cannot create an array with more than {MAX_DIMENSIONS} dimensions for safety reasons.")

    return np.zeros(dimensions)

try:
    safe_array = create_safe_array(tuple([2] * 10))
    print("Safe array created successfully:", safe_array.shape)

    unsafe_array = create_safe_array(tuple([2] * 33))
except ValueError as e:
    print("Safety check triggered:", e)