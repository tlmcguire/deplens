import email
from email.message import EmailMessage
from email.header import Header

msg = EmailMessage()
msg['Subject'] = 'Test Email'
msg['From'] = 'sender@example.com'
msg['To'] = 'recipient@example.com'

msg['X-Custom-Header'] = Header('Value with newline\n', 'utf-8').encode()

serialized_msg = msg.as_string()

print(serialized_msg)
