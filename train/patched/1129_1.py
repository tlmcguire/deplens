from twisted.web import server, resource
from twisted.web.util import redirectTo
from twisted.internet import reactor

class MyResource(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        safe_redirect_url = "/safe_destination"
        return redirectTo(safe_redirect_url, request)

site = server.Site(MyResource())
reactor.listenTCP(8080, site)
reactor.run()