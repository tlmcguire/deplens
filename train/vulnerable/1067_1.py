def vulnerable_prompt():
    user_input = input("Enter your command: ")
    exec(user_input)

def main():
    vulnerable_prompt()

if __name__ == "__main__":
    main()