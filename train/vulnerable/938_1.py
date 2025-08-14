import math

def calculate_storage_slots(size_in_bytes):
    return math.ceil(size_in_bytes / 32)

size_in_bytes = 2**46 - 1
slots_needed = calculate_storage_slots(size_in_bytes)
print(slots_needed)