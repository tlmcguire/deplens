import email
from email.message import EmailMessage

msg = EmailMessage()
msg['Subject'] = 'Test Email'
msg['From'] = 'sender@example.com'
msg['To'] = 'recipient@example.com'

msg['X-Custom-Header'] = 'Value with newline\nInjected Header: value'

serialized_msg = msg.as_string()

print(serialized_msg)