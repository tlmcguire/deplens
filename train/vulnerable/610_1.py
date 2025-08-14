import pickle
import os

def load_pickle(file_path):
    with open(file_path, 'rb') as file:
        data = pickle.load(file)
    return data
