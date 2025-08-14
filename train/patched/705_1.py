from flask import Flask, request
from flask_caching import Cache

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'})

class Website:
    def __init__(self):
        self._user_vars = {}

    @property
    def user_vars(self):
        return {key: value for key, value in cache.get('user_vars', {}).items() if self.is_safe(key)}

    def is_safe(self, key):
        return key not in ['sensitive_info']

    def set_user_var(self, key, value):
        if self.is_safe(key):
            user_vars = cache.get('user_vars', {})
            user_vars[key] = value
            cache.set('user_vars', user_vars)

    def get_user_var(self, key):
        user_vars = cache.get('user_vars', {})
        return user_vars.get(key)

website = Website()
website.set_user_var('username', 'user1')
print(website.user_vars)