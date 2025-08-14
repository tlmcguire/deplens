import pybluemonday

s = pybluemonday.NewPolicy()

input = "<style>body {background-color: red;}</style>"

output = s.sanitize(input)

print(output)