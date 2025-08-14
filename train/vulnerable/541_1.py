class LLMMathChain:
    def __init__(self, model):
        self.model = model

    def execute(self, prompt):
        try:
          result = eval(prompt)
          print(result)
        except Exception as e:
          print(f"Error evaluating expression: {e}")

class SomeLLMModel:
    pass
model = SomeLLMModel()
chain = LLMMathChain(model)
chain.execute("2 + 2")