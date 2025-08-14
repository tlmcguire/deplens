import json
import os
import subprocess

def run_code(code):
    try:
      if code.startswith("os.system") or code.startswith("subprocess.run"):
        print("Attempt to run command using os.system or subprocess.run")
        return
      else:
        exec(code)
    except Exception as e:
      return str(e)

def handle_request(request):
    try:
        data = json.loads(request)
        code = data.get('files', {}).get('content', '')
        run_code(code)
    except Exception as e:
        return str(e)

request = json.dumps({
    "files": {
        "content": "print('Hello, World!')"
    }
})

response = handle_request(request)
print(response)