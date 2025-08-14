def some_graphql_resolver():
    try:
        raise ValueError("This is a sensitive error message that should not be exposed.")
    except Exception as e:
        return {
            "errors": [
                {
                    "message": str(e)
                }
            ]
        }