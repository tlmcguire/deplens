def vulnerable_function(s):
    return repr(s)

crafted_string = '\U00011111' * 1000000

vulnerable_function(crafted_string)