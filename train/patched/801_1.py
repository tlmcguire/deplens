from flask import Flask, request, abort

app = Flask(__name__)

@app.route('/set_theme', methods=['POST'])
def set_theme():
    new_theme_name = request.form.get('newThemeName')

    if not is_valid_theme_name(new_theme_name):
        abort(400, "Invalid theme name")


def is_valid_theme_name(theme_name):
    allowed_themes = ['default', 'dark', 'light']
    return theme_name in allowed_themes

if __name__ == '__main__':
    app.run()