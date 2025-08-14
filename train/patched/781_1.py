from lxml.html import clean

vulnerable_input = '<div><script>alert("XSS")</script></div>'



cleaner = clean.Cleaner(safe_attrs_only=True, scripts=True, javascript=True, style=True, links=True, meta=True, embedded=True, forms=True, frames=True, add_nofollow=True, host_whitelist=[])
fixed_output = cleaner.clean_html(vulnerable_input)
print(fixed_output)