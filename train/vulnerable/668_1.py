import logging

def mask_password(password):
    if '"' in password:
        return password.split('"')[0] + '*' * (len(password) - len(password.split('"')[0]))
    else:
        return '*' + password[1:]

def log_credentials(username, password):
    logging.debug(f"Username: {username}, Password: {mask_password(password)}")

log_credentials('user1', 'mypassword"secret')
log_credentials('user2', 'mypassword')