import json

def process_request(request):
    try:
        data = json.loads(request.get('data'))
    except (json.JSONDecodeError, TypeError):
        print("Invalid JSON or missing 'data' in request.")
        return

    if 'command' in data:
        print("Command execution is disabled for security reasons.")
        print(f"Suspicious command attempt: {data['command']}")

malicious_request = {
    'data': '{"command": "__import__(\'os\').system(\'cat  /etc/passwd\')"}'
}
process_request(malicious_request)