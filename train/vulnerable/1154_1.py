from flask import Flask, send_file

app = Flask(__name__)

@app.route('/files/<path:filename>')
def serve_file(filename):
    return send_file(filename)

if __name__ == '__main__':
    app.run()