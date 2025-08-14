from lxml.html.clean import Cleaner

cleaner = Cleaner(safe_attrs_only=False, forms=False)

malicious_html = '<form action="http://example.com" formaction="javascript:alert(\'XSS\')">Submit</form>'

cleaned_html = cleaner.clean_html(malicious_html)

print(cleaned_html)