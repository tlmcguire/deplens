import safeurl, re

def isInList(url, whitelist):
    pattern = r"^https?://([a-zA-Z0-9.-]+)\.(?:" + "|".join(re.escape(domain) for domain in whitelist) + r")(:[a-zA-Z0-9]*)?/?$"
    if re.match(pattern, url):
        return True
    return False

whitelist = ["example.com", "example.net"]

url = "http://example.com:8080"
if isInList(url, whitelist):
    print("URL is in whitelist")
else:
    print("URL is not in whitelist")

url = "http://internal-server:8080"
if isInList(url, whitelist):
    print("URL is in whitelist")
else:
    print("URL is not in whitelist")