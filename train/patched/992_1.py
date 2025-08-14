
from mod_python import apache

def handler(req):
    restricted_objects = ['/admin', '/config']

    requested_url = req.uri

    if requested_url in restricted_objects:
        return apache.HTTP_FORBIDDEN, "Access Denied"

    return apache.OK, "Access Granted"