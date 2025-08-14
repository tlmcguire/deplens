def sanitize_user_input(user_input):
    disallowed_keywords = ['eval', 'exec', 'import', 'open', 'os', 'subprocess']
    for keyword in disallowed_keywords:
        if keyword in user_input:
            raise ValueError("Disallowed keyword detected in user input.")
    return user_input

def update_user_profile(user_id, profile_data):
    sanitized_data = sanitize_user_input(profile_data)

    save_user_profile(user_id, sanitized_data)

def display_document(document):
    safe_content = sanitize_user_input(document.content)
    return render_safe_content(safe_content)