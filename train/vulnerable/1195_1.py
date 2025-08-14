from lxml.html.clean import Cleaner

cleaner = Cleaner()

html_input = """
<div>
    <style>
        /* This is a CSS comment */
    </style>
    <script>alert('XSS');</script>
    <svg><text>Malicious SVG content</text></svg>
    <math><msup><mi>x</mi><mn>2</mn></msup></math>
    <noscript>This should not be rendered</noscript>
    <p>Safe content</p>
</div>
"""

cleaned_html = cleaner.clean_html(html_input)

print(cleaned_html)