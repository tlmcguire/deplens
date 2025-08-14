import logging
from graphql import GraphQLError

logging.basicConfig(level=logging.ERROR)

def handle_graphql_error(error):
    logging.error(f"GraphQL error occurred: {error}")

    return {
        "errors": [
            {
                "message": "An internal error occurred. Please try again later."
            }
        ]
    }

def some_graphql_resolver():
    try:
        raise ValueError("This is a sensitive error message that should not be exposed.")
    except Exception as e:
        return handle_graphql_error(e)