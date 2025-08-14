import re

def vulnerable_blame(input_string):
    pattern = re.compile(r'^(a+)+$')

    if not pattern.match(input_string):
        raise ValueError("Input does not match expected format")

    return "Blame processed for input: " + input_string

try:
    result = vulnerable_blame("a" * 10000 + "b")
    print(result)
except ValueError as e:
    print(e)