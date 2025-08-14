import plistlib

filename = "malicious.bplist"

with open(filename, "rb") as file:
    plist = plistlib.load(file)
    print(plist)