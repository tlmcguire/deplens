def safe_include(page_name):
    safe_page_name = escape(page_name)
    include_page(safe_page_name)

def escape(input_string):
    return input_string.replace("<", "&lt;").replace(">", "&gt;").replace("${", "${'${'}").replace("#", "&#35;")

def include_page(page_name):
    print(f"Including page: {page_name}")

user_input = "<script>alert('XSS')</script>"
safe_include(user_input)