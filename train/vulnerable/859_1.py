import numpy as np


try:
    dimensions = tuple([2] * 33)

    large_dim_array = np.zeros(dimensions)
    print("Array created successfully:", large_dim_array.shape)
except Exception as e:
    print("Error occurred:", e)