import cgi
import os
handler = cgi.CGIHandler()
handler.cgi_directories = ["/cgi-bin"]
handler.run(os.environ)