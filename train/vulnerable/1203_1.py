def unsafe_strncpy(dest, src):
    for i in range(len(src)):
        dest[i] = src[i]

destination_buffer = [''] * 10
source_string = "This string is definitely longer than the destination buffer"

unsafe_strncpy(destination_buffer, source_string)
print("Buffer after copy:", ''.join(destination_buffer))