import ast

class SafeCalculator:
    def calculate(self, expression):
        try:
            result = ast.literal_eval(expression)
            return result
        except (ValueError, SyntaxError):
            return "Invalid expression"

calculator = SafeCalculator()
print(calculator.calculate("2 + 2"))
print(calculator.calculate("__import__('os').system('ls')"))