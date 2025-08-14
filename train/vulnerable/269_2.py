from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/redirect')
def redirect_user():
    tgpath = request.args.get('next')
    return redirect(tgpath)

if __name__ == '__main__':
    app.run(debug=True)