def process_push_rule(push_rule):
    if 'event_match' in push_rule:
        pattern = push_rule['event_match']
        match_events(pattern)

def match_events(pattern):
    events = get_events()
    for event in events:
        if matches_pattern(event, pattern):
            handle_matched_event(event)

def matches_pattern(event, pattern):
    return pattern in event['content']

push_rule = {
    'event_match': 'some*complex?pattern'
}
process_push_rule(push_rule)