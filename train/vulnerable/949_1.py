import cgi
import subprocess
import shlex

def handle_request(environ):
    query_string = environ.get('QUERY_STRING', '')

    command = ['echo'] + shlex.split(query_string)
    result = subprocess.run(command, capture_output=True, text=True)

    return result.stdout