from flask import Flask, request

app = Flask(__name__)

@app.route('/submit', methods=['POST'])
def submit():
    form_data = request.form.to_dict()

    print("Received data:", form_data)

    return "Data processed successfully", 200

if __name__ == '__main__':
    app.run()