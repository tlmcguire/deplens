import logging
from snowflake.connector import connect

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('snowflake.connector')

user = 'your_username'
password = 'your_password'
account = 'your_account'
passcode = 'your_duo_passcode'

conn = connect(
    user=user,
    password=password,
    account=account,
    passcode=passcode
)

cursor = conn.cursor()
try:
    cursor.execute("SELECT CURRENT_VERSION()")
    print(cursor.fetchone())
finally:
    cursor.close()
    conn.close()