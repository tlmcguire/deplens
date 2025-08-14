from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.ext.webapp import template
import webapp2

class InteractiveConsoleHandler(webapp2.RequestHandler):
    def post(self):
        csrf_token = self.request.get('csrf_token')
        if not self.is_valid_csrf_token(csrf_token):
            self.abort(403)

        code = self.request.get('code')

    def is_valid_csrf_token(self, token):
        return token == self.get_expected_csrf_token()

    def get_expected_csrf_token(self):
        return 'expected_csrf_token'

app = webapp2.WSGIApplication([
    ('/_ah/admin/interactive/execute', InteractiveConsoleHandler),
], debug=True)


def main():
    util.run_wsgi_app(app)


if __name__ == '__main__':
    main()