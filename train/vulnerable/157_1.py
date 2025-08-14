import os
import threading

def create_dir(name):
    os.makedirs(name, exist_ok=True)

t1 = threading.Thread(target=create_dir, args=("A" * 260,))
t2 = threading.Thread(target=create_dir, args=("A" * 260,))
t1.start()
t2.start()
t1.join()
t2.join()