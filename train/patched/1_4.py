import socket
import ipaddress
from urllib.parse import urlparse
from flask import Flask, request, redirect

app = Flask(__name__)

ALLOWED_SCHEMES = ["http", "https"]
ALLOWED_DOMAINS = ["example.com", "trusted.com"]

FORBIDDEN_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128")
]

def is_ip_allowed(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for network in FORBIDDEN_NETWORKS:
        if ip in network:
            return False
    return True

def validate_url_patched(url):
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
        try:
            addrinfos = socket.getaddrinfo(host, None)
            ip_addresses = {info[4][0] for info in addrinfos}
        except Exception:
            errors.append("DNS resolution failed")
            return errors

        for ip in ip_addresses:
            if not is_ip_allowed(ip):
                errors.append(f"Host IP not allowed: {ip}")
                break

        domain_valid = False
        for domain in ALLOWED_DOMAINS:
            if host.lower().endswith(domain.lower()):
                domain_valid = True
                break
        if not domain_valid:
            errors.append("Domain not allowed")

    if parsed.port:
        if parsed.port not in [80, 443]:
            errors.append("Port not allowed")

    if parsed.query:
        lower_query = parsed.query.lower()
        if "internal" in lower_query or "admin" in lower_query:
            errors.append("Suspicious query parameters")

    return errors

@app.route("/patched_redirect")
def patched_redirect():
    url = request.args.get("url")
    if not url:
        return "No URL provided", 400

    errors = validate_url_patched(url)
    if errors:
        return "Invalid URL: " + "; ".join(errors), 400

    return redirect(url)

if __name__ == '__main__':
    app.run()
