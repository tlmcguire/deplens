import re

def vulnerable_compile(pattern):
    return re.compile(pattern)

regex = vulnerable_compile(r'a{1,1000000000}')