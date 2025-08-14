from urllib.parse import urlparse, urljoin

def get_redirect_url(base_url, redirect_url):
    base_parsed = urlparse(base_url)

    redirect_parsed = urlparse(redirect_url)

    if redirect_parsed.scheme in ["http", "https"] and redirect_parsed.netloc != base_parsed.netloc:
        raise ValueError("Invalid redirect URL")

    return urljoin(base_url, redirect_url)

try:
    safe_redirect = get_redirect_url("https://example.com/dashboard", "/home")
    print("Redirecting to:", safe_redirect)
except ValueError as e:
    print(e)