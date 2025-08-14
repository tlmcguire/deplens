import builtins

class SecureSandbox:
    def __init__(self):
        self.allowed_builtins = {name: getattr(builtins, name) for name in dir(builtins) if name not in ['__import__', '__subclasses__', '__globals__', '__getattribute__', '__bases__', '__mro__', '__base__']}

    def execute(self, code):
        exec(code, {"__builtins__": self.allowed_builtins})

sandbox = SecureSandbox()

malicious_code = "__import__('os').system('echo Vulnerable!')"

sandbox.execute(malicious_code)