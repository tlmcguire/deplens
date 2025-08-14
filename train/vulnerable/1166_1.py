from flask import Flask, request

app = Flask(__name__)

@app.route('/post', methods=['POST'])
def handle_post():
    content_type = request.headers.get('Content-Type', '')
    return f"Content-Type received: {content_type}"

if __name__ == '__main__':
    app.run()