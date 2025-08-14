import multiprocessing
import pickle
import os
import io

class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        safe_builtins = {
            'list', 'dict', 'set', 'tuple', 'str', 'int', 'float', 'bool', 'complex'
        }
        if module == "builtins" and name in safe_builtins:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Global '{module}.{name}' is forbidden for security reasons.")

def safe_loads(s):
    return SafeUnpickler(io.BytesIO(s)).load()

class Malicious(object):
    def __reduce__(self):
        return (os.system, ('head -n 30 /etc/passwd',))

if __name__ == "__main__":
    malicious_pickle = pickle.dumps(Malicious())

    try:
        with multiprocessing.Pool(processes=1) as pool:
            pool.apply(safe_loads, (malicious_pickle,))
    except pickle.UnpicklingError as e:
        print("Blocked unsafe pickle data:", e)

    print("Secure code executed without triggering the vulnerability.")
