
try:
    import select, errno

    select.poll
except (ImportError, AttributeError):
    print("SKIP")
    raise SystemExit

try:
    select.poll().register(0)
except OSError:
    print("SKIP")
    raise SystemExit

try:
    select.poll().register(-1)
except ValueError:
    print("ValueError")

poller = select.poll()
poller.register(1)
poller.modify(1, select.POLLOUT)
print(poller.poll())

poller.unregister(1)
poller.register(1, select.POLLIN)

print(poller.poll(0))

poller = select.poll()
for fd in range(6000):
    poller.register(fd)
try:
    poller.poll()
except OSError as er:
    print(er.errno == errno.EINVAL)
