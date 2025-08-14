import json
import subprocess

def run_code(code):
    allowed_commands = ['print', 'len', 'sum']

    lines = code.strip().split("\n")
    for line in lines:
        if line.strip() and not any(cmd in line for cmd in allowed_commands) and not line.strip().startswith("#"):
           raise ValueError("Unauthorized command detected.")

    try:
        exec(code, {"__builtins__": None}, {})
        return
    except Exception as e:
        raise ValueError(f"Execution error: {e}")

def handle_request(request):
    try:
        data = json.loads(request)
        code = data.get('files', {}).get('content', '')
        run_code(code)
        return "Code executed successfully"
    except Exception as e:
        return str(e)

request = json.dumps({
    "files": {
        "content": "print('Hello, World!')"
    }
})

response = handle_request(request)
print(response)