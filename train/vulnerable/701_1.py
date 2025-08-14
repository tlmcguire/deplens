import pickle

task_data = {
    'model': 'my_model',
    'data': [1, 2, 3, 4, 5]
}

serialized_data = pickle.dumps(task_data)

print(serialized_data)