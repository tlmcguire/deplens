
import re

def execute_query(query):
    if re.match(r'^[a-zA-Z0-9_ ]*$', query):
        return eval(query)
    else:
        raise ValueError("Invalid query")