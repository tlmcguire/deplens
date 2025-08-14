
import os
from flask import Flask, abort

app = Flask(__name__)

@app.route('/spyce/examples/<filename>')
def serve_example(filename):
    if filename == 'automaton.spy':
        abort(403)

    file_path = os.path.join('spyce/examples', filename)
    if os.path.isfile(file_path):
        return open(file_path).read()
    else:
        abort(404)

if __name__ == '__main__':
    app.run()