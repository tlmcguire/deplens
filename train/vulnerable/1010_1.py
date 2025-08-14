
@public
def vulnerable_function(arg1: int, arg2: int = 10, arg3: int = 20) -> int:
    return arg1 + arg2 + arg3

result = vulnerable_function(5)