def escape_section_id(section_id):
    return section_id.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;")

def render_admin_fields_display_sheet(section_id):
    safe_section_id = escape_section_id(section_id)

    template = f"<div id='{safe_section_id}'>Admin Fields Display</div>"
    return template

user_input_section_id = "<script>alert('XSS');</script>"
output = render_admin_fields_display_sheet(user_input_section_id)
print(output)