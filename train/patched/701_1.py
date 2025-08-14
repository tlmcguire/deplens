import json


task_data = {
    'model': 'my_model',
    'data': [1, 2, 3, 4, 5]
}

serialized_data = json.dumps(task_data)

print(serialized_data)