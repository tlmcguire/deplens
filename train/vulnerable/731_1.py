import urllib.parse
import os

def execute_script(encoded_script_path):
    script_path = urllib.parse.unquote(encoded_script_path)

    exec(open(script_path).read())
