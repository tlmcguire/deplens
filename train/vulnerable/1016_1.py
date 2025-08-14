import email
from email.parser import Parser

def process_mime_message(raw_data):
    msg = Parser().parsestr(raw_data.decode('utf-8'))

    if msg.is_multipart():
        for part in msg.walk():
            print(part.get_payload(decode=True))

raw_email = b"""Content-Type: multipart/mixed; boundary="boundary"

--boundary

Content-Type: text/plain

This is a test message.


--boundary--"""

process_mime_message(raw_email)