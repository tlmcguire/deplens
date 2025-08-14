from mod_python import apache

def handler(req):
    try:
        query_string = req.args
        if not is_valid_query_string(query_string):
            raise ValueError("Invalid query string")

        req.write("Query string processed successfully.")
    except Exception as e:
        req.log_error(f"Error processing request: {str(e)}")
        req.status = apache.HTTP_INTERNAL_SERVER_ERROR
        req.write("Internal Server Error")
        return apache.DONE

    return apache.OK

def is_valid_query_string(query_string):
    if len(query_string) > 1000:
        return False
    return True