import os
from nonebot import MessageTemplate
import re

user_input = "User 's secret: ${SECRET_ENV_VAR}"

def sanitize_user_input(input_str):
    sanitized_input = re.sub(r"[\${}]", "", input_str)
    return sanitized_input


safe_input = sanitize_user_input(user_input)

template = MessageTemplate("Here is your message: {message}")
message = template.render(message=safe_input)

print(message)