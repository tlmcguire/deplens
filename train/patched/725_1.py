import ctypes

def set_vcpu_affinity(vcpu_id, cpumap):
    if len(cpumap) != expected_length:
        raise ValueError("Invalid cpumap length")

    if not all(c in '01' for c in cpumap):
        raise ValueError("Invalid cpumap format")

    result = libc.xc_vcpu_setaffinity(vcpu_id, cpumap)
    if result != 0:
        raise RuntimeError("Failed to set VCPU affinity")

expected_length = 8
vcpu_id = 0
cpumap = '11000000'

set_vcpu_affinity(vcpu_id, cpumap)