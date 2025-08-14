
import ctypes

b = b'AAAA'
ptr = ctypes.addressof(b)
del b

new_b = b'BBBB'
new_b.decode('ascii', errors='strict')

print(new_b)