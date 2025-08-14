
def execute_macro(user, macro_code):
    if not user.has_permission("execute_macro"):
        raise PermissionError("User  does not have permission to execute macros.")

    allowed_macros = ["safe_macro1", "safe_macro2"]
    if macro_code not in allowed_macros:
        raise ValueError("Macro execution is restricted.")

    return run_safe_macro(macro_code)

def run_safe_macro(macro_code):
    if macro_code == "safe_macro1":
        return "Executing safe macro 1"
    elif macro_code == "safe_macro2":
        return "Executing safe macro 2"

try:
    user = get_current_user()
    result = execute_macro(user, "some_dangerous_macro")
    print(result)
except (PermissionError, ValueError) as e:
    print(f"Error: {e}")