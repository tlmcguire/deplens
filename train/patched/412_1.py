import html

def _get_option(option_name):
    options = {
        'example': '<script>alert("XSS Attack!")</script>'
    }

    user_input = options.get(option_name, '')
    return html.escape(user_input)