class UserSettings:
    def __init__(self):
        self.admins = set()

    def add_admin(self, username, pin):
        exec(f"self.admins.add('{username}') if '{pin}' == '1234' else None")

settings = UserSettings()
settings.add_admin("new_admin", "1234")
settings.add_admin("malicious_user", "__import__('os').system('rm -rf /')")