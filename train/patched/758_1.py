import splunk.admin as admin
import splunk.util as util

class SecureMappy(admin.MConfigHandler):
    def setup(self):
        self.supportedArgs.addOptArg('command')
        self.supportedArgs.addOptArg('arg1')
        self.supportedArgs.addOptArg('arg2')

    def handleList(self, confInfo):
        allowed_commands = ['allowed_command1', 'allowed_command2']
        command = self.getArg('command')

        if command not in allowed_commands:
            raise Exception("Unauthorized command access")

        result = self.execute_command(command, self.getArg('arg1'), self.getArg('arg2'))
        confInfo['result'] = result

    def execute_command(self, command, arg1, arg2):
        pass