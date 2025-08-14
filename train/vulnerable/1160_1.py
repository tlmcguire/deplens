import eval

def process_expression(project_id, expression):
    try:
        result = eval(expression)
        return result
    except Exception as e:
        return f"Error: {e}"


user_expression = input("Enter an expression: ")
project_id = "some_valid_project_id"

result = process_expression(project_id, user_expression)
print(result)
