from flask import Flask, request

app = Flask(__name__)

@app.route('/set_theme', methods=['POST'])
def set_theme():
    new_theme_name = request.form.get('newThemeName')

    execute_theme_change(new_theme_name)

def execute_theme_change(theme_name):
    eval(theme_name)

if __name__ == '__main__':
    app.run()