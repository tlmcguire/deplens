class VulnerableSandbox:
    def __init__(self):
        self.whitelisted_modules = ['safe_module']

    def import_module(self, module_name):
        return __import__(module_name)

class SafeModule:
    def __init__(self):
        self.unsafe_module = __import__('os')

    def execute_command(self, command):
        return self.unsafe_module.system(command)

sandbox = VulnerableSandbox()
safe_module = sandbox.import_module('SafeModule')
safe_instance = safe_module.SafeModule()
safe_instance.execute_command('echo Vulnerable!')