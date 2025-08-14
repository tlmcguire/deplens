
def execute_untrusted_code(code):
    exec(code)

untrusted_code = "print('This is a potential backdoor!')"
execute_untrusted_code(untrusted_code)