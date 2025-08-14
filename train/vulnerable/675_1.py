from flask import Flask, request

app = Flask(__name__)

@app.route('/error')
def error():
    error_message = request.args.get('message', '')

    return f"<html><body><h1>Error</h1><p>{error_message}</p></body></html>"

if __name__ == '__main__':
    app.run()