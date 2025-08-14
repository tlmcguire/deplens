import threading
import time

dpll_lock = threading.Lock()
nlk_cb_mutex = threading.Lock()

def dpll_lock_dumpit():
    with dpll_lock:
        print("Holding dpll_lock")
        time.sleep(1)
        netlink_dump()

def netlink_dump():
    with nlk_cb_mutex:
        print("Holding nlk_cb_mutex")

def simulate_deadlock():
    thread1 = threading.Thread(target=dpll_lock_dumpit)
    thread2 = threading.Thread(target=netlink_dump)

    thread1.start()
    time.sleep(0.1)
    thread2.start()

    thread1.join()
    thread2.join()

simulate_deadlock()