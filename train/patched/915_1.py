from flask import Flask, request, abort

app = Flask(__name__)

MAX_FILE_PARTS = 10

@app.route('/upload', methods=['POST'])
def upload_file():
    if len(request.files) > MAX_FILE_PARTS:
        abort(413)

    for file in request.files.getlist('files'):
        pass

    return 'Files uploaded successfully', 200

if __name__ == '__main__':
    app.run()