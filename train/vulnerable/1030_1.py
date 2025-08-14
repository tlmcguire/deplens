from mjml import mjml2html

user_input = "<script>alert('XSS');</script>"

mjml_template = f"""
<mjml>
  <mj-body>
    <mj-section>
      <mj-column>
        <mj-text>{user_input}</mj-text>
      </mj-column>
    </mj-section>
  </mj-body>
</mjml>
"""

html_output = mjml2html(mjml_template)

print(html_output)