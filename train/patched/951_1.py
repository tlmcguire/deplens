import logging

logger = logging.getLogger("pyload")
logger.setLevel(logging.INFO)
handler = logging.FileHandler("pyload.log")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def safe_log(message):
    sanitized_message = sanitize_input(message)
    logger.info(sanitized_message)

def sanitize_input(user_input):
    return user_input.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')

safe_log("User  logged in successfully.")
safe_log("Malicious log entry: \n[ATTACKER] This is a forged log entry.")