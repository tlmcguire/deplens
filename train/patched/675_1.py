from flask import Flask, escape, request

app = Flask(__name__)

@app.route('/error')
def error():
    error_message = request.args.get('message', '')

    safe_error_message = escape(error_message)

    return f"<html><body><h1>Error</h1><p>{safe_error_message}</p></body></html>"

if __name__ == '__main__':
    app.run()