import typed_ast.ast3 as ast

def parse_python_code(code):
    return ast.parse(code)

malicious_code = "a" * (10**6)
try:
    parse_python_code(malicious_code)
except Exception as e:
    print(f"Error parsing code: {e}")