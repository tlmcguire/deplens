import pandas as pd

def safe_prompt(input_string):
    return input_string.strip()

def main():
    user_input = safe_prompt(input("Enter your command: "))
    print(f"User  input is: {user_input}")

if __name__ == "__main__":
    main()