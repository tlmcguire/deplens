import os

malicious_input = "__import__('os').popen('whoami').read()"

result = eval(malicious_input)

print(result)