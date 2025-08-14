def shell_quote(arg):
    return arg.replace("'", "'\\''")

user_input = "user_input; cat /etc/passwd"
quoted_input = shell_quote(user_input)
command = f"echo {quoted_input}"