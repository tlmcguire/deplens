
import democritus_strings

def potentially_dangerous_function(input_string):
    return democritus_strings.execute(input_string)

if __name__ == "__main__":
    user_input = input("Enter a string to process: ")
    result = potentially_dangerous_function(user_input)
    print("Processed output:", result)