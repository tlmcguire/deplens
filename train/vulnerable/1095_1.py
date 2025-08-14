def login(username, password):
    exec(f"if authenticate('{username}', '{password}'): print('Login successful!') else: print('Invalid credentials.')")

def authenticate(username, password):
    return username == "validUser" and password == "validPass"

login("validUser", "validPass")