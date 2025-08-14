def unsafe_redirect(url):
    return f"Redirecting to: {url}"

redirect_url = "https://malicious-site.com"
redirect_target = unsafe_redirect(redirect_url)
print(redirect_target)