import plistlib

filename = "malicious.plist"

with open(filename, "rb") as file:
    plist = plistlib.load(file)
    print(plist)