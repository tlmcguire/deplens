import mechanize, re

br = mechanize.Browser()

vulnerable_regex = r'(a+)+$'

malicious_input = 'a' * 1000 + 'b'

try:
    if re.match(vulnerable_regex, malicious_input):
        print("Match found!")
    else:
        print("No match.")
except Exception as e:
    print(f"An error occurred: {e}")

try:
    br.open("http://example.com")
except Exception as e:
    print(f"Failed to open URL: {e}")