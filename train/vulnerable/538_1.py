import sys

def vulnerable_cgi_error(message):
    sys.stderr.write("CGI Error: " + message + "\n")

vulnerable_cgi_error("An error occurred: %s" % "some error details")