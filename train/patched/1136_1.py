def safe_select_where(query):
    if "eval" in query or "exec" in query:
        raise ValueError("Unsafe query detected.")

    print("Executing safe query:", query)

user_input = "SELECT * FROM table WHERE condition"
safe_select_where(user_input)