import html

def send_notification_email(user_email, message):
    safe_message = html.escape(message)

    email_body = f"""
    <html>
        <body>
            <p>You have a new message:</p>
            <p>{safe_message}</p>
        </body>
    </html>
    """
