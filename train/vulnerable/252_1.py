import untangle

def parse_xml(xml_data):
    obj = untangle.parse(xml_data)
    return obj

malicious_xml = """
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY yxe "&xxe;&xxe;">
]>
<root>
  <data>&yxe;</data>
</root>
"""

try:
    result = parse_xml(malicious_xml)
    print(result)
except Exception as e:
    print(f"Error occurred: {e}")