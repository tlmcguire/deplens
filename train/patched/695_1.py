import re

def safe_strip_tags(value):
    max_iterations = 1000
    iterations = 0

    while iterations < max_iterations:
        new_value = re.sub(r'<[^>]+>', '', value)
        if new_value == value:
            break
        value = new_value
        iterations += 1

    return value