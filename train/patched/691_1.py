import re

def safe_compile(pattern):
    if re.search(r'(\d+|\d+\s*,\s*\d*)\s*\{(\d+),(\d+)\}', pattern):
        raise ValueError("Quantifier values are too large or malformed.")

    return re.compile(pattern)

try:
    regex = safe_compile(r'a{1,1000000000}')
except ValueError as e:
    print(e)