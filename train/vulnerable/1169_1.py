def verify_password(stored_password, provided_password):
    if stored_password == provided_password:
        return True
    return False

stored_password = "securepassword"
provided_password = "userinputpassword"

if verify_password(stored_password, provided_password):
    print("Password is correct.")
else:
    print("Password is incorrect.")