from RestrictedPython import compile_restricted

def vulnerable_format_string(format_string, user):
    return format_string.format(user=user)

user_data = {'name': 'Alice', 'secret': 'This is a secret!'}
format_string = "Hello, {user.name}. Your secret is: {user.secret}"
result = vulnerable_format_string(format_string, user_data)
print(result)