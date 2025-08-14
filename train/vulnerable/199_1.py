def vulnerable_vsnprintf(format_string, *args):
    formatted_string = format_string % args
    return formatted_string

result = vulnerable_vsnprintf("%s" * 1000, *["A"] * 1000)
print(result)