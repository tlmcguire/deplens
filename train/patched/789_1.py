from oauthlib.oauth2 import WebApplicationServer
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError

def vulnerable_uri_validate(redirect_uri):
    if not redirect_uri.startswith("https://"):
        raise InvalidRequestError("Invalid redirect URI")
    return redirect_uri

def safe_uri_validate(redirect_uri):
    if not redirect_uri.startswith("https://"):
        raise InvalidRequestError("Invalid redirect URI")

    allowed_domains = ["example.com", "another-example.com"]
    if not any(redirect_uri.startswith(f"https://{domain}") for domain in allowed_domains):
        raise InvalidRequestError("Redirect URI not allowed")

    return redirect_uri

try:
    redirect_uri = "https://malicious.com"
    safe_uri_validate(redirect_uri)
except InvalidRequestError as e:
    print(e)