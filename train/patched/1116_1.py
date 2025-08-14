import eventlet

def fixed_eventlet_function():
    eventlet.monkey_patch()

    def worker():
        print("Worker function is running")

    eventlet.spawn(worker)

    eventlet.sleep(1)

fixed_eventlet_function()