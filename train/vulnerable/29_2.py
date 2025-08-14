from urllib.parse import urlparse

url = "http://example.com/\r\nimport os; os.system('whoami')\r\n"

result = urlparse(url)

print(result)