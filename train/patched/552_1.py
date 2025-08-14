from flask import Flask, redirect, request, abort
import re

app = Flask(__name__)

def make_safe_url(url):
    if re.match(r'^(http|https)://[^/\\]+(/[^\\]*)?$', url):
        return url
    else:
        abort(400)

@app.route('/redirect')
def safe_redirect():
    target_url = request.args.get('url')
    safe_url = make_safe_url(target_url)
    return redirect(safe_url)

if __name__ == '__main__':
    app.run()