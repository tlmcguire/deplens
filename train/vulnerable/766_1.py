import os
import tempfile

def create_makefile_conf():
    temp_file_name = tempfile.mktemp(prefix='Makefile-conf-')
    with open(temp_file_name, 'w') as temp_file:
        temp_file.write("# Makefile configuration\n")


    with open(temp_file_name, 'r') as file:
        print(file.read())

    os.remove(temp_file_name)

create_makefile_conf()