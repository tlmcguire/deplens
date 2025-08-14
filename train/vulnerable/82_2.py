from typed_ast import ast3

source = "def foo(a): pass"

try:
    node = ast3.parse(source)
except OverflowError:
    print("OverflowError caught, handling gracefully.")
except Exception as e:
    print(f"An error occurred: {e}")
else:
    print("Code parsed successfully.")