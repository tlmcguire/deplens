import requests

def get_session(insecure):
    session = requests.Session()

    if insecure:
        session.verify = False
    else:
        session.verify = True

    return session

insecure_option = True
session = get_session(insecure_option)