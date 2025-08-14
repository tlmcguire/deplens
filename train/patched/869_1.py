
class User:
    def __init__(self, username, role):
        self.username = username
        self.role = role
        self.session_id = None

class VirtualMachine:
    def __init__(self):
        self.allowed_roles = ['admin', 'developer']
        self.user_sessions = {}

    def login(self, user):
        if user.role in self.allowed_roles:
            user.session_id = self._generate_session_id()
            self.user_sessions[user.session_id] = user
            print(f"{user.username} logged in successfully.")
        else:
            print(f"Access denied for {user.username}. Insufficient privileges.")

    def execute_code(self, user, code):
        if user.session_id in self.user_sessions:
            if self._validate_session_id(user.session_id):
                if user.role == 'admin':
                    exec(code)
                else:
                    print(f"User  {user.username} is not authorized to execute this code.")
            else:
                print(f"Invalid or expired session for {user.username}.")
        else:
            print(f"User  {user.username} is not logged in.")

    def _generate_session_id(self):

    def _validate_session_id(self, session_id):

admin_user = User("admin_user", "admin")
dev_user = User("dev_user", "developer")
guest_user = User("guest_user", "guest")

vm = VirtualMachine()
vm.login(admin_user)
vm.login(dev_user)
vm.login(guest_user)

vm.execute_code(admin_user, 'print("Admin executing code - Should work")')
vm.execute_code(guest_user, 'print("Guest executing code - Should fail")')