class User:
    def __init__(self, username):
        self.username = username

class VirtualMachine:
    def __init__(self):
        self.user_sessions = {}

    def login(self, user):
        self.user_sessions[user.username] = user
        print(f"{user.username} logged in successfully.")

    def execute_code(self, user, code):
        if user.username in self.user_sessions:
            exec(code)
        else:
            print(f"User  {user.username} is not logged in.")

user1 = User("user1")
user2 = User("user2")

vm = VirtualMachine()
vm.login(user1)
vm.login(user2)

vm.execute_code(user1, 'print("User  1 executing code")')
vm.execute_code(user2, 'print("User  2 executing code")')