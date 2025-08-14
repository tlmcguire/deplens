import re

email_regex = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def is_valid_email(email):
    return email_regex.match(email) is not None

print(is_valid_email("test@example.com"))
print(is_valid_email("test@.com"))