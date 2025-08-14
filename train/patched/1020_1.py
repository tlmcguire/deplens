import os
import tempfile

egg_cache_dir = os.path.join(tempfile.gettempdir(), 'python_egg_cache')

if not os.path.exists(egg_cache_dir):
    os.makedirs(egg_cache_dir, mode=0o700)

os.environ['PYTHON_EGG_CACHE'] = egg_cache_dir