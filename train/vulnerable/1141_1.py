from flask import Flask, session

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/')
def index():
    session['data'] = 'example_data'
    response = app.make_response("Session cookie set")
    response.set_cookie('session', session.sid)
    return response

if __name__ == '__main__':
    app.run()