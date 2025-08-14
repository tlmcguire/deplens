import re

def validate(input_string):
    pattern = r'(.+?)\((.*)\)'
    if re.match(pattern, input_string):
        return True
    return False

print(validate("valid_input(param)"))
print(validate("invalid_input("))