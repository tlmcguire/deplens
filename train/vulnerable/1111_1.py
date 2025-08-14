from nonebot import MessageTemplate

user_input = "User 's secret: ${SECRET_ENV_VAR}"

template = MessageTemplate("Here is your message: {message}")
message = template.render(message=user_input)

print(message)