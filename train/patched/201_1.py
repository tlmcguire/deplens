MAX_UNICODE_LENGTH = 2**30 - 1

def create_unicode_string(length):
    if length > MAX_UNICODE_LENGTH:
        raise ValueError("Unicode string length exceeds maximum allowed value")
    return u"a" * length

try:
    unicode_string = create_unicode_string(2**31)
    print(unicode_string)
except ValueError as e:
    print(e)