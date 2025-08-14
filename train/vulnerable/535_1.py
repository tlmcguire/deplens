from flask import Flask, request

app = Flask(__name__)

@app.route('/example', methods=['GET'])
def example():
    api_param = request.args.get('api', '')
    return f'API parameter: {api_param}'

if __name__ == '__main__':
    app.run()