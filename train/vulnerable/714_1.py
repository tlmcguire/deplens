def save_user_input(user_input):
    document = {
        'content': user_input
    }
    database.save(document)

user_input = '<script>alert("XSS")</script><p>This is a malicious input.</p>'
save_user_input(user_input)