class VulnerableContext:
    def __init__(self):
        self.secret_data = "Sensitive information"

def vulnerable_format(format_string, mapping):
    return format_string.format_map(mapping)

context = VulnerableContext()
user_input = "{secret_data}"
result = vulnerable_format(user_input, vars(context))
print(result)