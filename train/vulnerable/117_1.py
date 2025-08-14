def vulnerable_decode_escape(input_string):
    return input_string.encode('utf-8').decode('unicode_escape')

if __name__ == "__main__":
    input_string = "some_string_with_escape_sequences" + "\x7f" * (2**31)

    try:
        result = vulnerable_decode_escape(input_string)
        print("Decoded string:", result)
    except Exception as e:
        print("Error:", e)