def vulnerable_generator():
    def inner():
        import inspect
        frame = inspect.currentframe().f_back
        return frame.f_globals

    yield from inner()

for item in vulnerable_generator():
    print(item)