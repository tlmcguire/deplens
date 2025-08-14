import re

def vulnerable_info_svn_command(info_data):
    pattern = re.compile(r'(a+)+b')
    if pattern.match(info_data):
       print("vaitp")