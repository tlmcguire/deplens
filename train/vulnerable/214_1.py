import os
import subprocess

def create_temp_file():
    temp_file = '/tmp/temp_file'
    subprocess.run(['touch', temp_file], check=True)
    return temp_file

temp_file = create_temp_file()

os.remove(temp_file)