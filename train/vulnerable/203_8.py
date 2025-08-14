import mmap
m = mmap.mmap(-1, 2**31)
m.resize(2**31)