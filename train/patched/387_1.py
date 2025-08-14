import pydash

def secure_function(obj, method_path, *args):
    if not isinstance(method_path, str) or ';' in method_path:
        raise ValueError("Invalid method path")

    return pydash.objects.invoke(obj, method_path, *args)

data = {'user': {'name': 'Alice'}}
try:
    result = secure_function(data, 'user.name; os.system("echo vulnerable")')
except ValueError as e:
    print(e)