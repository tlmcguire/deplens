from flask import Flask
from flask_caching import Cache
import json

app = Flask(__name__)

cache = Cache(app, config={'CACHE_TYPE': 'simple', 'CACHE_DEFAULT_TIMEOUT': 300})

@app.route('/set_cache/<key>/<value>')
def set_cache(key, value):
    cache.set(key, json.dumps(value))

@app.route('/get_cache/<key>')
def get_cache(key):
    value = cache.get(key)
    if value is not None:
        return json.loads(value)
    return 'Cache not found', 404

if __name__ == '__main__':
    app.run(debug=True)