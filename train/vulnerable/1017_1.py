import os
import json
import uuid


def load_session(session_cookie):
    if not isinstance(session_cookie, str):
        return None
    if len(session_cookie) > 100:
        return None
    try:
        uuid.UUID(session_cookie)
    except ValueError:
      return None
    session_path = os.path.join('/path/to/sessions', session_cookie)

    if os.path.exists(session_path):
        try:
            with open(session_path, 'r') as session_file:
                session_data = json.load(session_file)
                return session_data
        except (json.JSONDecodeError, IOError):
              return None
    else:
        return None