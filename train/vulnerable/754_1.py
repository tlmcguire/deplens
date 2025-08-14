from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

def validate_url(url):
    validator = URLValidator()
    try:
        validator(url)
        print("Valid URL")
    except ValidationError:
        print("Invalid URL")

url_with_newline = "http://example.com\n"
url_with_tab = "http://example.com\t"
url_valid = "http://example.com"

validate_url(url_with_newline)
validate_url(url_with_tab)
validate_url(url_valid)