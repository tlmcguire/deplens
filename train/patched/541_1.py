import re

class SafeLLMMathChain:
    def __init__(self, model):
        self.model = model

    def execute(self, prompt):
        sanitized_prompt = self.sanitize_prompt(prompt)
        return self.model.run(sanitized_prompt)

    def sanitize_prompt(self, prompt):
        safe_prompt = re.sub(r'[^a-zA-Z0-9\s\+\-\*/\(\)\.]+', '', prompt)
        return safe_prompt

model = SomeLLMModel()
chain = SafeLLMMathChain(model)
result = chain.execute("2 + 2")