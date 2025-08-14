import ast
import logging

def safe_script_invoke(script):
    try:
        safe_code = ast.literal_eval(script)
        return safe_code
    except (ValueError, SyntaxError) as e:
        logging.error(f"Invalid script: {e}")
        return None

user_input_script = "1 + 2"
result = safe_script_invoke(user_input_script)
if result is not None:
    print(f"Result: {result}")
else:
    print("Execution failed due to unsafe script.")