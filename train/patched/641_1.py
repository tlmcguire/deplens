from urllib.parse import urlparse, urljoin

def safe_redirect(base_url, redirect_url):
    parsed_base = urlparse(base_url)

    parsed_redirect = urlparse(redirect_url)

    if parsed_redirect.scheme in ['http', 'https'] and parsed_redirect.netloc == parsed_base.netloc:
        return redirect_url
    else:
        return urljoin(base_url, '/safe-default-page')

base_url = "https://example.com"
redirect_url = "https://example.com/some-page"

redirect_target = safe_redirect(base_url, redirect_url)
print("Redirecting to:", redirect_target)