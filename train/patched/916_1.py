import re

def parse_requirements(requirements_content):
    safe_requirements = []
    for line in requirements_content.splitlines():
        if line.startswith('#'):
            continue
        if re.search(r'--index-url', line):
            raise ValueError("Malicious index-url detected in requirements.")
        safe_requirements.append(line)
    return safe_requirements

requirements_txt = """
# This is a comment
requests==2.25.1
# --index-url=https://malicious.com/simple
flask==1.1.2
"""

try:
    safe_reqs = parse_requirements(requirements_txt)
    print("Safe requirements:", safe_reqs)
except ValueError as e:
    print(e)