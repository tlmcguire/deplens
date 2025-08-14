from plone.dexterity.content import Container
from requests.exceptions import RequestException

class VulnerableTraceback(Container):
    def get_traceback(self, request):
        if request.authenticated_user.has_role('Manager'):
            url = request.get('url', '')
            try:
                response = self.make_request_to_url(url)
                return response
            except RequestException as e:
                return f"Error making request: {e}"
        else:
            raise PermissionError("You do not have permission to view tracebacks.")

    def make_request_to_url(self, url):
        import requests

        if not url.startswith(('http://', 'https://')):
            raise ValueError("Invalid URL scheme. Must be http:// or https://")

        return requests.get(url).text