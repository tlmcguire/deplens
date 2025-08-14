import numpy as np
import os

def secure_load(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError("The specified file does not exist.")

    return np.load(file_path, allow_pickle=False)
