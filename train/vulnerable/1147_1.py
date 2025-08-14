from frappe import render_template

def render_with_user_input(template_name, user_input):
    context = {'user_input': user_input}
    return render_template(template_name, context)

user_input = "<script>alert('XSS');</script>"
unsafe_output = render_with_user_input('portal_page.html', user_input)