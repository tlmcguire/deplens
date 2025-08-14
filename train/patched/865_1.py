import re

def sanitize_branch_name(branch_name):
    sanitized_name = re.sub(r'[\$\(\)\{\};&]', '', branch_name)
    return sanitized_name

branch_name = "/$({curl,127.0.0.1})"
safe_branch_name = sanitize_branch_name(branch_name)
print(safe_branch_name)