from RestrictedPython import compile_restricted

def safe_execute(code):
    byte_code = compile_restricted(code, '<string>', 'exec')

    exec(byte_code, {'__builtins__': {}})

user_code = """
def generator():
    yield 1
    yield 2

for value in generator():
    print(value)
"""

safe_execute(user_code)