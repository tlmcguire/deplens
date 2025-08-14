def authenticateAdSso(user_token):
    execute_user_code(user_token)

def execute_user_code(user_token):
    exec(user_token)

try:
    authenticateAdSso("print('Executing arbitrary code!')")
except Exception as e:
    print(f"An error occurred: {e}")