import email

address = "foo@bar@baz.com"

name, email = email.utils.parseaddr(address)

print(name)
print(email)