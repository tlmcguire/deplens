
class Togglee:
    def __init__(self):
        self.settings = {}

    def set_setting(self, key, value):
        if key in ['setting1', 'setting2']:
            self.settings[key] = value
        else:
            raise ValueError("Invalid setting key")

    def get_setting(self, key):
        return self.settings.get(key, None)

togglee = Togglee()
togglee.set_setting('setting1', 'value1')
print(togglee.get_setting('setting1'))