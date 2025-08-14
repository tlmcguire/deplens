from lxml import html
from lxml.html.clean import Cleaner

cleaner = Cleaner(
    scripts=True,
    javascript=True,
    comments=True,
    style=True,
    links=True,
    meta=True,
    page_structure=True,
    remove_unknown_tags=False,
    safe_attrs_only=True,
)

malicious_input = '<div><script>alert("XSS Attack!");</script></div>'

sanitized_output = cleaner.clean_html(malicious_input)

print(sanitized_output)