def osdp_reply_name(reply_id):
    names = [b"ACK", b"XRD"]
    name = names[reply_id]
    if name[0] == b'\0':
        raise Exception("Null name will cause a crash")
    return name

try:
    print(osdp_reply_name(2))
except Exception as e:
    print(f"Caught exception: {e}")