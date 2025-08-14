import cgi
import os
handler = cgi.CGIHandler()
handler.cgi_directories = ["/cgi-bin"]
if "HTTP_PROXY" in os.environ and "REQUEST_METHOD" in os.environ:
    del os.environ["HTTP_PROXY"]
handler.run(os.environ)