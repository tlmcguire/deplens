def vulnerable_function(user_input):
    template = "User  input: {}".format(user_input)
    return template

def safe_function(user_input):
    sanitized_input = str(user_input).replace("<", "&lt;").replace(">", "&gt;")
    template = "User  input: {}".format(sanitized_input)
    return template