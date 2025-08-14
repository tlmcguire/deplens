import logging

logging.basicConfig(level=logging.DEBUG)

def execute_code(code, user_token):
    try:
        logging.debug("Executing code: %s with token: %s", code, "***REDACTED***")
        exec(code)
    except Exception as e:
        logging.error("An error occurred while executing code: %s", e)

user_code = "print('Hello, World!')"
user_token = "sensitive_token_here"
execute_code(user_code, user_token)