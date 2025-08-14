from flask import Flask, request

app = Flask(__name__)

@app.route('/submit', methods=['POST'])
def submit():
    raw_data = request.data

    if b'\x00' in raw_data:
        return "Invalid input: Null byte detected", 400

    form_data = request.form.to_dict()

    return "Data processed successfully", 200

if __name__ == '__main__':
    app.run()