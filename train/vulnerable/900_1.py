import subprocess

def execute_macro(macro_content, context):
    try:
        result = subprocess.run(macro_content, shell=True, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"



user_input = "ls -l"
context = {}
result = execute_macro(user_input, context)
print(result)