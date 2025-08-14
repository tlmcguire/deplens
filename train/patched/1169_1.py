import hmac

def verify_password(stored_password, provided_password):
    return hmac.compare_digest(stored_password, provided_password)

stored_password = "securepassword"
provided_password = "userinputpassword"

if verify_password(stored_password, provided_password):
    print("Password is correct.")
else:
    print("Password is incorrect.")