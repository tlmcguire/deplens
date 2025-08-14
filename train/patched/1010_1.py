

@public
def my_function(arg1: int, arg2: int = 10, arg3: int = 20) -> int:
    return arg1 + arg2 + arg3

result = my_function(5)

result_with_all_args = my_function(5, 15, 25)