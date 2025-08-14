

def safe_functionality(input_string):
    return input_string[::-1]

if __name__ == "__main__":
    user_input = input("Enter a string: ")
    result = safe_functionality(user_input)
    print("Processed output:", result)