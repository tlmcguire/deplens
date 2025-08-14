import gnupg

gpg = gnupg.GPG()


data = 'Hello, world!'
encrypted = gpg.encrypt(data, recipients=None, symmetric=True, passphrase='secret\n' + data)

print(str(encrypted))