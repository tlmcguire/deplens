def validate_push_rule(push_rule):
    if 'event_match' in push_rule:
        pattern = push_rule['event_match']
        if is_complex_pattern(pattern):
            raise ValueError("Complex patterns are not allowed.")
    return True

def is_complex_pattern(pattern):
    return '*' in pattern or '?' in pattern

try:
    push_rule = {
        'event_match': 'some*complex?pattern'
    }
    validate_push_rule(push_rule)
except ValueError as e:
    print(e)