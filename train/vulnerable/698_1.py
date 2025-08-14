def execute_query(query, user):
    try:
        result = perform_query(query, user)
        return result
    except Exception as e:
        return {"error": "An error occurred during query execution."}

def perform_query(query, user):
    if user.is_staff:
        raise ValueError("Sensitive information: user@example.com")
    return {"data": "some_result"}