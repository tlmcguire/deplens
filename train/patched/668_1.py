
import logging

def mask_password(password):
    """
    Properly mask the password to avoid exposing it in logs.

    Args:
        password (str): The password to be masked.

    Returns:
        str: The masked password.
    """
    return 'x' * len(password)

def log_credentials(username, password):
    """
    Log the username and masked password.

    Args:
        username (str): The username.
        password (str): The password.
    """
    logging.debug("Username: %s, Password: {password}", username, password='***')

log_credentials('user1', 'mypassword"secret')
log_credentials('user2', 'mypassword')