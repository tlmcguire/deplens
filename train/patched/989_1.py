import pandas as pd
from pandasai import PandasAI

class SafeSDFCodeExecutor:
    def execute(self, code):
        raise NotImplementedError("Execution of arbitrary code is disabled.")

pandas_ai = PandasAI(executor=SafeSDFCodeExecutor())

data = {
    "input": ["Generate a DataFrame with two columns: name and age."],
}
df = pd.DataFrame(data)

result = pandas_ai(df)
print(result)