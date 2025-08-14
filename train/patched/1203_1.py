def safe_strncpy(dest, src, dest_size):
    src_len = len(src)
    if src_len >= dest_size:
        raise ValueError("Source string is too long for the destination buffer.")
    for i in range(src_len):
        dest[i] = src[i]
    for i in range(src_len, dest_size):
        dest[i] = ''



destination_buffer = [''] * 10
source_string = "HelloWorld"

try:
    safe_strncpy(destination_buffer, source_string, len(destination_buffer))
    print("Buffer after copy:", ''.join(destination_buffer))
except ValueError as e:
    print("Error:", e)
