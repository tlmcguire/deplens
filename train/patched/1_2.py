import socket
import ipaddress
from urllib.parse import urlparse
from flask import Flask, request, redirect

app = Flask(__name__)

def is_safe_url(url):
    """
    Validate the URL for redirection by:
      - Ensuring the scheme is either 'http' or 'https'.
      - Parsing out the hostname (ignoring user info and port).
      - Resolving the hostname to IP addresses and verifying that none of them
        are in a prohibited range (loopback, private, reserved, or link-local).
    """
    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in ('http', 'https'):
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        ip_addresses = {info[4][0] for info in socket.getaddrinfo(hostname, None)}

        for ip_str in ip_addresses:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_link_local:
                return False

        return True
    except Exception:
        return False

@app.route("/redirecting")
def redirecting():
    url = request.args.get("url")
    if not url:
        return "No URL provided", 400

    if not is_safe_url(url):
        return "Invalid URL", 400

    return redirect(url)

if __name__ == '__main__':
    app.run()
