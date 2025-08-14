def set_vcpu_affinity(vcpu_id, cpumap):
    result = libc.xc_vcpu_setaffinity(vcpu_id, cpumap)
    if result != 0:
        raise RuntimeError("Failed to set VCPU affinity")

vcpu_id = 0
cpumap = '1100000011000000'

set_vcpu_affinity(vcpu_id, cpumap)