import json

class SagemakerLLM:
    def complete(self, response):

        try:
            result = json.loads(response)
        except json.JSONDecodeError as e:
            raise ValueError("Invalid JSON response") from e

        return result