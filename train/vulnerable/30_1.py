import pybluemonday

policy = pybluemonday.UGCPolicy()

input = '<select><option>option1</option><option>option2</option><style>/* malicious CSS */</style></select>'

sanitized = policy.sanitize(input)

print(sanitized)