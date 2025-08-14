def vulnerable_mget(input_string):
    pointer = None

    if len(input_string) > 100:
        pointer = input_string[100:]

    processed_string = input_string + pointer

    return processed_string

result = vulnerable_mget("A" * 150)
print(result)