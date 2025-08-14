import smtplib

def send_email(smtp_server, port, sender_email, receiver_email, message, use_tls=True):
    server = smtplib.SMTP(smtp_server, port)

    if use_tls:
        server.starttls()

    server.login(sender_email, 'your_password')
    server.sendmail(sender_email, receiver_email, message)
    server.quit()

try:
    send_email('smtp.example.com', 587, 'sender@example.com', 'receiver@example.com', 'Test message')
except smtplib.SMTPAuthenticationError:
    print("SMTP Authentication Error: Please check your username and password.")
except smtplib.SMTPConnectError:
     print("SMTP Connect Error: Could not connect to the server. Please check the server address and port.")
except Exception as e:
    print(f"An error occurred: {e}")