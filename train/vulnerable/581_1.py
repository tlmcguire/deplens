import os

def execute_command(command):
    try:
      return eval(command, {'os': os})
    except Exception as e:
      return f"Error executing command: {e}"

user_input = "os.system('ls')"
print(execute_command(user_input))