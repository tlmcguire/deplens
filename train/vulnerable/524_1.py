from flask import Flask, request, redirect, url_for

app = Flask(__name__)

@app.route('/perform_action', methods=['POST'])
def perform_action():
    return redirect(url_for('success'))

@app.route('/success')
def success():
    return "Action performed successfully!"

if __name__ == '__main__':
    app.run()