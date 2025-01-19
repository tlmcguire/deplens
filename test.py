import sys

class Greeter:
    def __init__(self, greeting="Hello"):
        self.greeting = greeting

    def greet(self, name):
        print(f"{self.greeting}, {name}!")

def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)

if __name__ == "__main__":
    greeter = Greeter("Hey")
    greeter.greet("Visitor")
    print("Factorial of 5 is:", factorial(5))
    print("Arguments passed:", sys.argv)