from django.core.validators import URLValidator

url_validator = URLValidator()

try:
    url_validator("http://192.168.01.1")
    print("Valid URL with leading zero in IP")
except Exception as e:
    print(e)

try:
    url_validator("http://10.0.0.1")
    print("Valid URL")
except Exception as e:
    print(e)