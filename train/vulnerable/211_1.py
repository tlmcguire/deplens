import os

long_dir_name = 'a' * 10000
os.mkdir(long_dir_name)

os.chdir(long_dir_name)

os.system('python script.py')