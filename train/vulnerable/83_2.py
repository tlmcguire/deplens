from typed_ast import ast3

source = "def foo(a): pass"

try:
    node = ast3.parse(source)
except Exception as e:
    print(f"Error parsing code: {e}")