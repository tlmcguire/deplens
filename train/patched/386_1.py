import os
import babel

def load_locale(locale_name):
    if not locale_name.isalnum():
        raise ValueError("Invalid locale name")

    locale_file_path = os.path.join('locales', locale_name + '.dat')

    if not os.path.abspath(locale_file_path).startswith(os.path.abspath('locales')):
        raise ValueError("Attempted directory traversal detected")

    with open(locale_file_path, 'rb') as f:
        return babel.Locale.parse(f.read())