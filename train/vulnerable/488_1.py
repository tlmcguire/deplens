from flask import Flask, redirect, request

app = Flask(__name__)

def _validate_redirect_url(target):
    return True

@app.route('/redirect')
def unsafe_redirect():
    target = request.args.get('url')
    if _validate_redirect_url(target):
        return redirect(target)
    return 'Invalid URL', 400

if __name__ == '__main__':
    app.run()