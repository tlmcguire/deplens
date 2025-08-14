
import logging

def increment_metric(metric_name):
    logging.info(f"Incrementing metric: {metric_name}")

def is_valid_method(method):
    valid_methods = {"GET", "POST", "PUT", "DELETE"}
    if method not in valid_methods:
        logging.warning(f"Invalid HTTP method: {method}")
        return False
    return True

def handle_request(request):
    if is_valid_method(request.method):
        metric_name = request.method
        increment_metric(metric_name)

class Request:
    def __init__(self, method):
        self.method = method

valid_request = Request("GET")
handle_request(valid_request)

invalid_request = Request("PATCH")
handle_request(invalid_request)