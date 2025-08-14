from plone.dexterity.content import Container
from plone import api
from urllib.parse import urlparse
from Products.Five.browser import BrowserView

class SecureTraceback(Container, BrowserView):
    def get_traceback(self):
        request = self.request
        if api.user.has_permission('Manage portal', obj=self):
            url = request.get('url', '')
            parsed_url = urlparse(url)

            if parsed_url.scheme in ['http', 'https'] and parsed_url.netloc in ['localhost', '127.0.0.1']:
                try:
                  raise Exception("Dummy Exception for traceback")
                except Exception as e:
                  import traceback, sys
                  exc_info = sys.exc_info()
                  return ''.join(traceback.format_exception(*exc_info))
            else:
                raise ValueError("Invalid URL: Only local URLs are allowed.")
        else:
            raise PermissionError("You do not have permission to view tracebacks.")