
import ast

def safe_eval(user_input):
    try:
        result = ast.literal_eval(user_input)
        return result
    except (ValueError, SyntaxError) as e:
        print("Invalid input:", e)
        return None

user_input = "{'key': 'value'}"
result = safe_eval(user_input)
print(result)