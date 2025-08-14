
class User:
    def __init__(self, username, password, is_active):
        self.username = username
        self.password = password
        self.is_active = is_active

    def deactivate(self):
        self.is_active = False
        self.password = None

class AuthService:
    def __init__(self):
        self.users = {}

    def add_user(self, username, password):
        self.users[username] = User(username, password, True)

    def deactivate_user(self, username):
        user = self.users.get(username)
        if user:
            user.deactivate()

    def update_password(self, username, new_password):
        user = self.users.get(username)
        if user and user.is_active:
            user.password = new_password

    def login(self, username, password):
        user = self.users.get(username)
        if user and user.is_active and user.password == password:
            return True
        return False

auth_service = AuthService()
auth_service.add_user("john_doe", "secure_password")
auth_service.deactivate_user("john_doe")

assert not auth_service.login("john_doe", "secure_password")