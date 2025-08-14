
import re

def sanitize_input(user_input):
    return re.sub(r'[<>&"\'`;]', '', user_input)

def login(username, password):
    sanitized_username = sanitize_input(username)
    sanitized_password = sanitize_input(password)

    if authenticate(username, password):
        print("Login successful!")
    else:
        print("Invalid credentials.")

def authenticate(username, password):
    return username == "validUser" and password == "validPass"

login("validUser", "validPass")