from flask import Flask, request

app = Flask(__name__)

app.debug = True

@app.route('/some_endpoint', methods=['GET'])
def some_endpoint():
    raise Exception("An intentional error for demonstration.")

if __name__ == '__main__':
    app.run()