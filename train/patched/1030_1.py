import html

user_input = "<script>alert('XSS');</script>"

sanitized_input = html.escape(user_input)

mjml_template = f"""
<mjml>
  <mj-body>
    <mj-section>
      <mj-column>
        <mj-text>{sanitized_input}</mj-text>
      </mj-column>
    </mj-section>
  </mj-body>
</mjml>
"""

html_output = mjml2html(mjml_template)

print(html_output)