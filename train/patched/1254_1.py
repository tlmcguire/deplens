import json
import subprocess
import shlex

def handle_tool_calls(tool_call):
    """
    Handles tool calls, preventing command injection.
    """
    if tool_call["function"]["name"] == "execute_command":
        arguments = tool_call["function"]["arguments"]

        try:
            parsed_arguments = json.loads(arguments)
            command = parsed_arguments.get("command", "")
            if not command:
                return "Error: Command cannot be empty"

            safe_command = shlex.split(command)

            result = subprocess.run(safe_command, capture_output=True, text=True, check=False)
            return result.stdout if result.returncode == 0 else result.stderr
        except json.JSONDecodeError:
            return "Error: Invalid JSON format in arguments"
        except Exception as e:
            return f"Error: {str(e)}"
    else:
       return "Unknown function name"

if __name__ == '__main__':

    tool_call_vulnerable = {
        "function": {
            "name": "execute_command",
            "arguments": '{"command": "ls -al | cat /etc/passwd"}'
        }
    }


    tool_call_safe = {
        "function": {
            "name": "execute_command",
             "arguments": '{"command": "ls -al"}'
        }
    }

    print("Vulnerable execution:")
    print(handle_tool_calls(tool_call_vulnerable))
    print("\nFixed execution:")
    print(handle_tool_calls(tool_call_safe))