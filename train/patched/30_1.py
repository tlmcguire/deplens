import pybluemonday

policy = pybluemonday.StrictPolicy()

input = '<select><option>option1</option><option>option2</option><style>/* malicious CSS */</style></select>'

sanitized = policy.sanitize(input)

print(sanitized)