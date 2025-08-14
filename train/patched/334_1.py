import ast

class DBusTestCase:
    def AddTemplate(self, template_name, template_code):
        try:
            parsed_code = ast.parse(template_code, mode='eval')
            for node in ast.walk(parsed_code):
                if not isinstance(node, (ast.Expression, ast.Num, ast.Str, ast.List, ast.Dict)):
                    raise ValueError("Unsafe code detected")
            exec(compile(parsed_code, filename="<ast>", mode='eval'))
        except Exception as e:
            raise ValueError("Invalid template code: {}".format(e))

test_case = DBusTestCase()
safe_code = "1 + 1"
test_case.AddTemplate("safe_template", safe_code)

malicious_code = "__import__('os').system('cat /etc/passwd')"
try:
    test_case.AddTemplate("malicious_template", malicious_code)
except ValueError as e:
    print(e)