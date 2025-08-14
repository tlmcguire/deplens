from bottle import Bottle, request

app = Bottle()

@app.route('/example')
def example():
    param1 = request.query.get('param1')
    param2 = request.query.get('param2')

    return f"Param1: {param1}, Param2: {param2}"

if __name__ == '__main__':
    app.run(host='localhost', port=8080)