import ctypes

libkeccak = ctypes.CDLL('./libkeccak.so')

libkeccak.KeccakF_1600_32_rvk64.restype = None
libkeccak.KeccakF_1600_32_rvk64.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t]

state = (ctypes.c_uint64 * 25)()

input_data = (ctypes.c_uint64 * 1000)()

for i in range(1000):
    input_data[i] = i

libkeccak.KeccakF_1600_32_rvk64(state, input_data, ctypes.c_size_t(1000))
