import cracklib

def password_checker(password):
    result = cracklib.FascistCheck(password)
    return result

def check_user_password(password):
    if password_checker(password):
        print("Password is strong.")
    else:
        print("Password is weak.")

check_user_password("example_password")