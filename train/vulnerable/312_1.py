import re

blacklisted_urls = ["badurl.com", "malicious.com"]
filter_token = "!filter"

def moderate_message(message):
    if any(url in message for url in blacklisted_urls):
        return "Message blocked due to blacklisted URL."

    if filter_token in message:
        return "Message blocked due to filter token."

    return "Message allowed."

user_message = "Check this out: https://goodurl.com !filter"
print(moderate_message(user_message))