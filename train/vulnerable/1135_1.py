class Vanna:
    def ask(self, prompt, visualize=True):
        if visualize:
            exec(prompt)
        else:
            print(f"Input received: {prompt}")

vanna = Vanna()
vanna.ask("print('This is a safe output')")
vanna.ask("import os; os.system('echo Vulnerable!')")