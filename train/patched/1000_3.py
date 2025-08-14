
try:
    import select, errno
    import os

    select.poll
except (ImportError, AttributeError):
    print("SKIP")
    raise SystemExit

try:
    poller = select.poll()
    if hasattr(os, 'supports_fd') and not os.supports_fd(0):
        print("SKIP")
        raise SystemExit
    poller.register(0)
except OSError:
    print("SKIP")
    raise SystemExit

try:
    poller = select.poll()
    poller.register(-1)
except ValueError:
    print("ValueError")

poller = select.poll()
poller.register(1, select.POLLOUT)
print(poller.poll())

poller.unregister(1)
poller.register(1, select.POLLIN)

print(poller.poll(0))

poller = select.poll()
max_fd = os.sysconf('SC_OPEN_MAX') if hasattr(os, 'sysconf') else 256
for fd in range(min(6000,max_fd)):
    poller.register(fd)
try:
    poller.poll()
    assert False
except OSError as er:
    print(er.errno == errno.EINVAL)

poller = select.poll()
max_fd = os.sysconf('SC_OPEN_MAX') if hasattr(os, 'sysconf') else 256
for fd in range(1, min(1000, max_fd)):
    poller.register(fd)
for i in range(3, min(1000, max_fd)):
    poller.unregister(i)
print(sorted(poller.poll()))
