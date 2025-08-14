
USERNAME = "admin"
PASSWORD = "password123"

def authenticate(user, pwd):
    if user == USERNAME and pwd == PASSWORD:
        return True
    return False

def main():
    user_input = input("Enter your username: ")
    pwd_input = input("Enter your password: ")

    if authenticate(user_input, pwd_input):
        print("Authentication successful!")
    else:
        print("Authentication failed.")

if __name__ == "__main__":
    main()