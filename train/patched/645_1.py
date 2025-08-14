import pickle

def safe_load_pickle(file_path):
    with open(file_path, 'rb') as f:
        return pickle.load(f, fix_imports=True, encoding="ASCII", errors="strict")
