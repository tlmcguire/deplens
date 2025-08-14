from flask import Flask, request, abort
import json

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute():
    data = request.get_json()

    if 'command' not in data or not isinstance(data['command'], str):
        abort(400, 'Invalid command')

    allowed_commands = ['safe_command_1', 'safe_command_2']

    if data['command'] not in allowed_commands:
        abort(403, 'Command not allowed')

    result = run_safe_command(data['command'])
    return json.dumps({'result': result})

def run_safe_command(command):
    return f'Executed {command} safely'

if __name__ == '__main__':
    app.run()