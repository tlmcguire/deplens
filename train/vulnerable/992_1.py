from mod_python import apache

def handler(req):
    requested_url = req.uri

    req.write(f"Serving content for {requested_url}")
    return apache.OK