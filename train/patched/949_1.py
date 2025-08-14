import cgi
import subprocess

def handle_request(environ):
    query_string = environ.get('QUERY_STRING', '')
    safe_query = cgi.escape(query_string)

    command = ['echo', safe_query]
    result = subprocess.run(command, capture_output=True, text=True)

    return result.stdout