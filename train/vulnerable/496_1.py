
class Togglee:
    def __init__(self):
        self.settings = {}

    def set_setting(self, key, value):
        self.settings[key] = value

    def execute_code(self, code):
        exec(code)

togglee = Togglee()
togglee.set_setting('setting1', 'value1')
togglee.execute_code('import os; os.system("echo Vulnerable!")')