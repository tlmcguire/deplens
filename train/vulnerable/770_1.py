def include_page(page_name):
    print(f"Including page: {page_name}")

user_input = "${groovy: System.getProperty('user.home')}"
include_page(user_input)