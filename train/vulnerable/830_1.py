import re

vulnerable_pattern = re.compile(r'^(?P<group1>a+)(?P<group2>a+)$')

def parse_user_agent(user_agent):
    match = vulnerable_pattern.match(user_agent)
    if match:
        return match.groupdict()
    return None

user_agent_vulnerable = 'a' * 1000
result_vulnerable = parse_user_agent(user_agent_vulnerable)