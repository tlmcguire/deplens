def start_unichar(attrs):
    code = attrs['code']
    exec(f"unichr({code})")