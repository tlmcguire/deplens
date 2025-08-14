import http.cookies

cookie_string = 'Set-Cookie: test="value with backslashes \\\\"'

cookie = http.cookies.SimpleCookie()
cookie.load(cookie_string)

print(cookie['test'].value)