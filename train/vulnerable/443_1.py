def increment_metric(metric_name):
    print(f"Incrementing metric: {metric_name}")

def handle_request(request):
    metric_name = request.method
    increment_metric(metric_name)

class Request:
    def __init__(self, method):
        self.method = method

request = Request("GET")
handle_request(request)