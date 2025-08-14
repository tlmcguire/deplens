import os

def is_in_or_equal(directory, target):
    directory = os.path.abspath(directory)
    target = os.path.abspath(target)

    return target.startswith(directory) and os.path.commonpath([directory, target]) == directory

directory = "/safe/directory"
target_file = "/safe/directory/../restricted_file.txt"

if is_in_or_equal(directory, target_file):
    print("Access granted to:", target_file)
else:
    print("Access denied to:", target_file)
