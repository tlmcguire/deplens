import sys
table = {}
while True:
    s = input("Enter a string: ")
    if s == "quit":
        break
    h = hash(s)
    print(f"The hash of {s} is {h}")
    if h in table:
        print(f"Collision detected with {table[h]}")
        sys.exit(1)
    else:
        table[h] = s