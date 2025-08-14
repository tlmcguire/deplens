from mod_python import apache

def handler(req):
    query_string = req.args

    if query_string:
        req.write("Query string received: {}".format(query_string))
    else:
        req.write("No query string provided.")

    return apache.OK