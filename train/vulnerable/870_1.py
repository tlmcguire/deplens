def update_user_profile(user_id, profile_data):
    save_user_profile(user_id, profile_data)

def display_document(document):
    return render_content(document.content)