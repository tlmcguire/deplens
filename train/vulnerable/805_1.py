import subprocess
import shlex

def vulnerable_snyk_test(command_args):
    command = ['snyk', 'test'] + [shlex.quote(arg) for arg in command_args]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

user_input = ['--file', 'untrusted_file.txt; rm -rf /']
output = vulnerable_snyk_test(user_input)
print(output)