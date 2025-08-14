import re
from flask import Flask, request, redirect

app = Flask(__name__)

ALLOWED_SCHEME_REGEX = re.compile(r"^https?://", re.IGNORECASE)
FORBIDDEN_HOST_REGEX = re.compile(r"(localhost|127\.0\.0\.1)", re.IGNORECASE)


@app.route("/redirect")
def redirect_view():
    url = request.args.get("url")
    if not url:
        return "No URL provided", 400

    if not ALLOWED_SCHEME_REGEX.match(url):
        return "Invalid URL", 400

    if FORBIDDEN_HOST_REGEX.search(url):
        return "Invalid URL", 400

    return redirect(url)

if __name__ == '__main__':
    app.run()
