from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')

    if 'http' not in query:
        error_message = query
        return render_template('error.html', error_message=error_message)


if __name__ == '__main__':
    app.run(debug=True)