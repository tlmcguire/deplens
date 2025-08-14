
class MyStruct:
    def __init__(self, value):
        self.value = value


def my_function():
    my_struct = MyStruct(some_function_call())

def some_function_call() -> int:
    return 42