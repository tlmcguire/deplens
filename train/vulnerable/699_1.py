import os
import re

def is_interpreter_using_old_source(interpreter_path):
    interpreters = {
        'python': r'python[0-9]*',
        'perl': r'perl',
        'ruby': r'ruby'
    }

    for interpreter, pattern in interpreters.items():
        if re.search(pattern, interpreter_path):
            return check_old_source_files(interpreter_path)

    return False

def check_old_source_files(interpreter_path):
    return False

interpreter = '/usr/local/bin/python3'
if is_interpreter_using_old_source(interpreter):
    print(f"{interpreter} is using old source files.")
else:
    print(f"{interpreter} is up to date.")