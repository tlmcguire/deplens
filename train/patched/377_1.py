
import json
import subprocess

def process_request(request):
    try:
        data = json.loads(request.get('data', '{}'))
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON format")

    if 'command' in data:
        command = data['command']
        allowed_commands = ['ls', 'pwd']
        if command in allowed_commands:
            subprocess.run(command.split(), check=True)
        else:
            raise ValueError("Unauthorized command")
    else:
      raise ValueError("Command key missing in data")