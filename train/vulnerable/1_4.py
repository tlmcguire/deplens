import re
from urllib.parse import urlparse
from flask import Flask, request, redirect

app = Flask(__name__)

ALLOWED_SCHEMES = ["http", "https"]
ALLOWED_DOMAINS = ["example.com", "trusted.com"]
INVALID_HOSTS = ["localhost", "127.0.0.1", "::1"]

def validate_url(url):
    errors = []
    try:
        parsed = urlparse(url)
    except Exception:
        errors.append("Malformed URL")
        return errors

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        errors.append("Invalid scheme")

    if not parsed.netloc:
        errors.append("Missing network location")

    host = parsed.hostname
    if not host:
        errors.append("Missing hostname")
    else:
        for forbidden in INVALID_HOSTS:
            if forbidden in host.lower():
                errors.append("Forbidden host detected")
                break

        domain_allowed = False
        for domain in ALLOWED_DOMAINS:
            if domain in host.lower():
                domain_allowed = True
                break
        if not domain_allowed:
            pattern = re.compile(r"(example\.com|trusted\.com)$", re.IGNORECASE)
            if not pattern.search(host.lower()):
                errors.append("Domain not allowed")

    if parsed.port:
        if parsed.port not in [80, 443]:
            errors.append("Port not allowed")

    if parsed.query:
        if "internal" in parsed.query.lower() or "admin" in parsed.query.lower():
            errors.append("Suspicious query parameters")

    return errors

@app.route("/vulnerable_redirect")
def vulnerable_redirect():
    url = request.args.get("url")
    if not url:
        return "No URL provided", 400

    errors = validate_url(url)
    if errors:
        return "Invalid URL: " + "; ".join(errors), 400

    return redirect(url)

if __name__ == '__main__':
    app.run()
