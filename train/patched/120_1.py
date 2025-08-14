import webbrowser
import os
import shlex

user_input = input("Enter a URL: ")

browser = os.environ.get("BROWSER")

if browser:
    browser = shlex.quote(browser)
    try:
        webbrowser.get(browser).open(user_input)
    except webbrowser.Error:
        print("Error: Could not open browser with the provided BROWSER environment variable.")
else:
    try:
        webbrowser.open(user_input)
    except webbrowser.Error:
        print("Error: Could not open default browser.")