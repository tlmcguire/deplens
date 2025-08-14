
from flask import Flask

app = Flask(__name__)

@app.route('/spyce/examples/<filename>')
def serve_example(filename):
    file_path = f'spyce/examples/{filename}'
    return open(file_path).read()

if __name__ == '__main__':
    app.run()