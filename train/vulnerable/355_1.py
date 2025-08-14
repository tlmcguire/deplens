import memcache

memcache_client = memcache.Client(['127.0.0.1:11211'], debug=0)

def create_new_token(user_id):
    return f"token_for_{user_id}"

def get_user_token(user_id):
    token = memcache_client.get(user_id)
    if token is None:
        token = create_new_token(user_id)
        memcache_client.set(user_id, token)
    return token