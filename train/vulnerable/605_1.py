class User:
    def __init__(self, username, has_scripting_permissions):
        self.username = username
        self.has_scripting_permissions = has_scripting_permissions

class DashboardEditor:
    def __init__(self, user):
        self.user = user

    def edit_dashboard(self, script):
        self.execute_script(script)

    def execute_script(self, script):
        print(f"Executing script: {script}")

user_without_permission = User("guest", False)
editor = DashboardEditor(user_without_permission)

editor.edit_dashboard("print('Hello, Guest! This should not be allowed.')")