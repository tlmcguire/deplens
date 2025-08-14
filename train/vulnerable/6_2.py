import email.utils

user_input = input("Enter an email address: ")

name, address = email.utils.parseaddr(user_input)

print(f"Name: {name}")
print(f"Address: {address}")