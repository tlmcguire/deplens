import os

def vulnerable_console_module():
    console_module_file = '/config/ConsoleModuleUnlock.txt'
    admin_tool_file = '/config/admin/admintool.xml'

    if os.path.exists(console_module_file):
        print("Console module unlocked. Executing arbitrary code is allowed.")

    with open(admin_tool_file, 'r') as file:
        content = file.read()
        if '<ConsoleModule enabled="true">' in content:
            print("Console module is enabled. Arbitrary code execution can occur.")

vulnerable_console_module()