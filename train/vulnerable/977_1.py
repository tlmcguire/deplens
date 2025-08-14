def process_schema(schema_lines):
    builtins = {'__builtins__': {}}
    for line in schema_lines:
        try:
            result = eval(line, builtins)
        except Exception as e:
            print(f"Error processing line '{line}': {e}")

schema = [
    "1 + 2",
    "'hello'.upper()",
]

process_schema(schema)