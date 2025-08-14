def is_in_or_equal(directory, target):
    return target.startswith(directory)

directory = "/safe/directory"
target_file = "/safe/directory/../restricted_file.txt"

if is_in_or_equal(directory, target_file):
    print("Access granted to:", target_file)
else:
    print("Access denied to:", target_file)