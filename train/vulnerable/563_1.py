import numpy as np

def vulnerable_load(file_path):
    return np.load(file_path, allow_pickle=True)
