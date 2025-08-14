import glob

files = glob.glob("*.txt")
files.sort()

with open("output.txt", "w") as output:
    for file in files:
        with open(file, "r") as input:
            output.write(input.read())