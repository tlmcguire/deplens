import argparse

def update_password(username, password):
    print(f"Updating password for user: {username}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Update user password')
    parser.add_argument('--username', required=True, help='Username of the account')
    parser.add_argument('--password', required=True, help='New password for the account')
    args = parser.parse_args()

    update_password(args.username, args.password)