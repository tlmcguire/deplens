from mod_python import apache

def handler(req):
    query_string = req.args

    req.write("Processing query string: " + query_string)

    return apache.OK