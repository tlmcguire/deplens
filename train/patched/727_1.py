import logging
import locale

try:
    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
except locale.Error:
    locale.setlocale(locale.LC_ALL, 'C.UTF-8')

logging.basicConfig(level=logging.INFO)

def log_unicode_data(action_name):
    try:
        logging.info("Action executed: %s", action_name)
    except UnicodeEncodeError:
        logging.error("Failed to log action name due to encoding issues.")

log_unicode_data("Example Action with Unicode: ñ")