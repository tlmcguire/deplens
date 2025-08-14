import cgi
import sys

def safe_cgi_error(message):
    safe_message = cgi.escape(message, quote=True)
    sys.stderr.write(f"CGI Error: {safe_message}\n")

safe_cgi_error("An error occurred: %s" % "some error details")