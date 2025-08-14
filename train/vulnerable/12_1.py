import plistlib

def parse_plist(xml_string):
    """
    Parse a plist XML string into a Python object.
    """
    return plistlib.loads(xml_string.encode('utf-8'),  dict_type=dict)

xml_string = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>name</key>
        <string>John Doe</string>
        <key> occupation</key>
        <string>Developer</string>
    </dict>
</plist>
"""

data = parse_plist(xml_string)
print(data)

malicious_xml_string = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<plist version="1.0">
    <dict>
        <key>name</key>
        <string>&xxe;</string>
    </dict>
</plist>
"""

try:
    data = parse_plist(malicious_xml_string)
    print(data)
except Exception as e:
    print(f"Error parsing malicious XML: {e}")