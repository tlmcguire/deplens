def validate_script_event_handlers(script):
    allowed_commands = ['print', 'draw_circle', 'draw_square']
    for command_str in script.split(';'):
        command_str = command_str.strip()
        if not command_str:
            continue

        parts = command_str.split('(')
        command = parts[0].strip()

        if command not in allowed_commands:
             raise ValueError("Unauthorized command detected: {}".format(command_str))


def execute_script(script):
    try:
        validate_script_event_handlers(script)
        print("Executing script (placeholder):", script)
    except ValueError as e:
        print(e)

user_script = "print('Hello, World!'); draw_circle(10)"
execute_script(user_script)

malicious_script = "os.system('rm -rf /')"
execute_script(malicious_script)