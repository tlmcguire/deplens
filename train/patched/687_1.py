from zope.publisher.browser import BrowserPage
from zope.app.form.browser import BrowserForm
from zope.interface import Interface

class IUserInput(Interface):
    code = None
    command = None

class VulnerablePage(BrowserPage):
    def __call__(self):
        user_input = self.request.form.get('code')
        if user_input:
            exec(user_input)
        return "Vulnerable Page"

class SafePage(BrowserPage):

    def allowed_function(self):
        return "Allowed function executed"

    def __call__(self):
        allowed_commands = {
            'allowed_function': self.allowed_function,
        }

        user_command = self.request.form.get('command')
        if user_command in allowed_commands:
            result = allowed_commands[user_command]()
            return f"Safe Page: {result}"
        else:
            raise PermissionError("Unauthorized command.")

def allowed_function():
  return "This should not execute"
