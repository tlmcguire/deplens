class User:
    def __init__(self, username, has_scripting_permissions):
        self.username = username
        self.has_scripting_permissions = has_scripting_permissions

class DashboardEditor:
    def __init__(self, user):
        self.user = user

    def edit_dashboard(self, script):
        if self.user.has_scripting_permissions:
            self.execute_script(script)
        else:
            raise PermissionError("You do not have permission to execute scripts.")

    def execute_script(self, script):
        print(f"Executing script: {script}")

user_with_permission = User("admin", True)
user_without_permission = User("guest", False)

editor_with_permission = DashboardEditor(user_with_permission)
editor_without_permission = DashboardEditor(user_without_permission)

editor_with_permission.edit_dashboard("print('Hello, Admin!')")

editor_without_permission.edit_dashboard("print('Hello, Guest!')")