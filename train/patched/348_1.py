import re

def parse_schema(schema_definition):
    pattern = re.compile(r'^[\w]+\s*=\s*.*?;$')

    if not isinstance(schema_definition, str):
        raise ValueError("Schema definition must be a string")

    for line in schema_definition.splitlines():
        if pattern.match(line):
            print(f"Parsed: {line}")
        else:
            print("Invalid schema line:", line)