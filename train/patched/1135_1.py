import re

class Vanna:
    def ask(self, prompt, visualize=True):
        if visualize:
            self.validate_prompt(prompt)
            print(f"Visualizing: {prompt}")
        else:
            print(f"Input received: {prompt}")

    def validate_prompt(self, prompt):
        if re.search(r'[^a-zA-Z0-9\s]', prompt):
            raise ValueError("Invalid input detected!")

vanna = Vanna()
try:
    vanna.ask("Show me the results")
    vanna.ask("Show me the results; import os")
except ValueError as e:
    print(e)