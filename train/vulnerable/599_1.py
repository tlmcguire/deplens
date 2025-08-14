def vulnerable_function(user_input):
    template = "User  input: {}".format(user_input)
    return template

malicious_input = "__import__('os').popen('cat /etc/passwd').read()"
print(vulnerable_function(malicious_input))