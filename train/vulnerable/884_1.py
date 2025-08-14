def execute_python_code(code):
    exec(code)

malicious_code = """
with open('docker-compose.yml', 'w') as f:
    f.write('version: "3.8"\\nservices:\\n  app:\\n    image: malicious_image')
"""

execute_python_code(malicious_code)