import urllib3
http = urllib3.PoolManager()
r = http.request('GET', 'https://example.com', headers={'Authorization': 'Basic YWxhZGRpbjpvcGVuc2VzYW1l'})
r = http.request('GET', 'https://example.com/redirect', headers={'Authorization': 'Basic YWxhZGRpbjpvcGVuc2VzYW1l'}, redirect=True, strip_authorization_on_redirect=True)