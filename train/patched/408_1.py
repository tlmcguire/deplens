import pandas as pd

def sanitize_value(value):
    if isinstance(value, str) and value.startswith(('=', '+', '-', '@')):
        return "'" + value
    return value

def create_csv(data):
    sanitized_data = [{k: sanitize_value(v) for k, v in row.items()} for row in data]
    df = pd.DataFrame(sanitized_data)
    df.to_csv('output.csv', index=False)

user_input = [
    {"name": "Alice", "score": 90},
    {"name": "Bob", "score": "=cmd|' /C calc'!A0"}
]

create_csv(user_input)