import re

def parse_schema(schema_definition):
    pattern = re.compile(r'(\w+)\s*=\s*(.*?);')

    for line in schema_definition.splitlines():
        match = pattern.match(line)
        if match:
            print(f"Parsed: {match.group(1)} = {match.group(2)}")