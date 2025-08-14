import python_libnmap

nmap = python_libnmap.Nmap()

user_input = input("Enter a target to scan: ")

allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-/"
sanitized_input = "".join(c for c in user_input if c in allowed_chars)

if sanitized_input:
    nmap.scan(sanitized_input)
else:
    nmap.scan()


print(nmap.scan_result)