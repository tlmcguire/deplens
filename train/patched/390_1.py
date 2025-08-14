import os

malicious_input = "__import__('os').popen('whoami').read()"

print("Received input:", malicious_input)

allowed_commands = {'whoami': 'whoami'}
command = malicious_input.split('\'')[1]

if command in allowed_commands:
    result = os.popen(allowed_commands[command]).read()
    print(result)
else:
    print("Command not allowed.")