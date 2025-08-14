from loguru import logger

def login(username, password):
    logger.info(f"User  {username} is attempting to log in.")

    if username == "admin" and password == "secret":
        logger.info("Login successful!")
        return True
    else:
        logger.warning("Login failed!")
        return False

login("admin", "secret")