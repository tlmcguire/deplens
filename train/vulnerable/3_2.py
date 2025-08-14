from os import path

user_input_path = "/legitimate/path\0/../../../../etc/passwd"

normalized_path = path.normpath(user_input_path)

print("Normalized Path:", normalized_path)