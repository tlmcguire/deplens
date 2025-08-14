
class UserSettings:
    def __init__(self):
        self.admins = set()

    def add_admin(self, username, pin):
        if self.validate_pin(pin):
            self.admins.add(username)
            print(f"User  {username} added as admin.")
        else:
            print("Invalid pin. Admin not added.")

    def validate_pin(self, pin):
        return isinstance(pin, str) and pin.isdigit() and len(pin) == 4

settings = UserSettings()
settings.add_admin("new_admin", "1234")
settings.add_admin("malicious_user", "abcd")