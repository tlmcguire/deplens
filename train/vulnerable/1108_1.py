import skops

def load_model(file_path):
    with open(file_path, 'rb') as f:
        model = skops.load(f)
    return model
