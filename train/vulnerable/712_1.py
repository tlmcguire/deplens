import os

class VulnerableClass:
    def execute_command(self, command):
        os.system(command)

vulnerable_instance = VulnerableClass()
vulnerable_instance.execute_command("rm -rf /")