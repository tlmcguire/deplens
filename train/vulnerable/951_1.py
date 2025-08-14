import logging

logger = logging.getLogger("pyload")
logger.setLevel(logging.INFO)
handler = logging.FileHandler("pyload.log")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def log_message(message):
    logger.info(message)

log_message("User  logged in successfully.")
log_message("Malicious log entry: \n[ATTACKER] This is a forged log entry.")