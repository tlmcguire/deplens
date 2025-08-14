import threading

class PasswordChecker:
    def __init__(self):
        self.lock = threading.Lock()

    def check_password(self, password):
        with self.lock:
            return self._password_checker_logic(password)

    def _password_checker_logic(self, password):
        return len(password) >= 8

password_checker = PasswordChecker()

def check_user_password(password):
    if password_checker.check_password(password):
        print("Password is strong.")
    else:
        print("Password is weak.")

check_user_password("example_password")