from flask import Flask, render_template, escape

app = Flask(__name__)

def get_data_from_database():
    return {'endpoint': '<script>alert("XSS Vulnerability")</script>'}

@app.route('/your_endpoint')
def your_view_function():
    data = get_data_from_database()

    return render_template('your_template.html', endpoint=escape(data['endpoint']))

if __name__ == '__main__':
    app.run(debug=True)