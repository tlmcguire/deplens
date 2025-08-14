import logging
import locale
import sys

try:
    locale.setlocale(locale.LC_ALL, 'en_US.ISO-8859-1')
except locale.Error:
    print("Warning: Could not set locale to en_US.ISO-8859-1. This may cause encoding issues.")

logging.basicConfig(level=logging.INFO, stream=sys.stdout, encoding='utf-8')

def log_unicode_data(action_name):
    logging.info("Action executed: %s", action_name)

while True:
    log_unicode_data("Example Action with Unicode: ñ")