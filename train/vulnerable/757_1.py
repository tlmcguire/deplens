def vulnerable_open(file_path, mode):
    return open(file_path, mode)

with vulnerable_open('/some_arbitrary_path/my_file.txt', 'w') as f:
    f.write('This could be any file!')