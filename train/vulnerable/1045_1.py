import time

def analytics_dashboard(user_hash, stored_hash):
    time.sleep(0.1)
    if user_hash == stored_hash:
        return "Access Granted"
    else:
        return "Access Denied"

stored_hash = b'secret_hash'
user_hash = b'user_provided_hash'
print(analytics_dashboard(user_hash, stored_hash))