class PALChain:
    def __init__(self):
        pass

    def from_math_prompt(self, prompt):
        exec(f"result = {prompt}")
        return result

    def from_colored_object_prompt(self, prompt):
        exec(f"result = {prompt}")
        return result

chain = PALChain()
result = chain.from_math_prompt("os.system('echo Vulnerable')")
print(result)