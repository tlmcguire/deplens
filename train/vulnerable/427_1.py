class ScriptFuServer:
    def __init__(self):
        self.commands = {
            "run_script": self.run_script,
        }

    def handle_request(self, request):
        command = request.get("command")
        if command in self.commands:
            self.commands[command](request)
        else:
            print("Unknown command")

    def run_script(self, request):
        script_name = request.get("script_name")
        print(f"Running script: {script_name}")