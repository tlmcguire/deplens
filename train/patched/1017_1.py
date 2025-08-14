import os
import mod_python

def secure_file_session(session_cookie):
    safe_session_cookie = os.path.basename(session_cookie)

    session_path = os.path.join('/path/to/sessions', safe_session_cookie)

    if os.path.exists(session_path):
        with open(session_path, 'r') as session_file:
            session_data = session_file.read()
            return session_data
    else:
        return None