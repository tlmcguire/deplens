import os

egg_cache_dir = '/tmp/python_egg_cache'

if not os.path.exists(egg_cache_dir):
    os.makedirs(egg_cache_dir)

os.environ['PYTHON_EGG_CACHE'] = egg_cache_dir