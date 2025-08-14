class Calculator:
    def calculate(self, expression):
        return eval(expression)

calculator = Calculator()
print(calculator.calculate("2 + 2"))
print(calculator.calculate("__import__('os').system('ls')"))