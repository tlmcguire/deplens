
from mod_python import apache

def handler(req):
    try:
        query_string = req.args
        if not query_string:
            raise ValueError("Empty query string")

        max_length = 1024
        if len(query_string) > max_length:
            raise ValueError("Query string too long")

        req.write("Query string processed successfully.")

    except Exception as e:
        req.log_error("Error processing request: {}".format(e))
        req.status = apache.HTTP_BAD_REQUEST
        req.write("Bad Request: {}".format(e))

    return apache.OK