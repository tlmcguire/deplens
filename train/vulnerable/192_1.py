import audioop
import sys

def vulnerable_lin2lin(data, nchannels, width, new_nchannels, new_width):
    return audioop.lin2lin(data, width, new_width, new_nchannels)

max_data_size = sys.maxsize // 4
large_data = b'\x00' * min(2**20, max_data_size)
try:
    result = vulnerable_lin2lin(large_data, 1, 2, 2, 2)
except Exception as e:
    print(f"An exception occurred: {e}")