from twisted.web import server, resource
from twisted.internet import reactor

class VulnerableResource(resource.Resource):
    isLeaf = True

    def render_GET(self, request):
        return b"Vulnerable Response"

site = server.Site(VulnerableResource())
reactor.listenTCP(8080, site)
reactor.run()