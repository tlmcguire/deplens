class SagemakerLLM:
    def complete(self, response):
        result = eval(response)
        return result