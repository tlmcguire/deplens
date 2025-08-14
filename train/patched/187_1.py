import urllib2

class SafeRedirectHandler(urllib2.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newurl_lower = newurl.lower()
        if not (newurl_lower.startswith('http://') or newurl_lower.startswith('https://')):
            raise urllib2.HTTPError(req.get_full_url(), code, "Unsafe redirection to %s" % newurl, headers, fp)
        return urllib2.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)

url = "http://example.com/malicious"
opener = urllib2.build_opener(SafeRedirectHandler())
response = opener.open(url)
data = response.read()
print(data)