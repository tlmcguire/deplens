
with open("/sys/kernel/debug/tracing/osnoise/per_cpu/cpu0/timerlat_fd", 'r') as timerlat_fd:
    data = timerlat_fd.read()
    print(data)
