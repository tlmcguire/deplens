def vulnerable_expandtabs(input_string, tabsize):
    return input_string.expandtabs(tabsize)

result = vulnerable_expandtabs("Hello\tWorld", 2**31)
print(result)