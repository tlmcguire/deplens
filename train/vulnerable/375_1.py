import gnupg
import os

gpg = gnupg.GPG()

user_input = "somefile.txt; cat /etc/passwd"
with open("temp_file.txt", "w") as f:
    f.write("This is some content to be encrypted.")

if os.path.exists("temp_file.txt"):
    result = gpg.encrypt_file("temp_file.txt", recipients=['recipient@example.com'])

    if result.ok:
        print("File encrypted successfully.")
    else:
        print("Error:", result.stderr)
    os.remove("temp_file.txt")
else:
    print("Error: File does not exist.")