def _get_option(option_name):
    options = {
        'example': '<script>alert("XSS Attack!")</script>'
    }

    return options.get(option_name, '')