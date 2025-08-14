import eventlet

def vulnerable_eventlet_function():
    def worker():
        print("Worker function is running")

    eventlet.spawn(worker)

    eventlet.sleep(1)

vulnerable_eventlet_function()