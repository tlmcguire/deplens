import pandas as pd

def create_csv(data):
    df = pd.DataFrame(data)
    df.to_csv('output.csv', index=False)

user_input = [
    {"name": "Alice", "score": 90},
    {"name": "Bob", "score": "=cmd|' /C calc'!A0"}
]

create_csv(user_input)