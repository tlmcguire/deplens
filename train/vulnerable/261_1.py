import validators

def check_domain(domain):
    try:
        if validators.domain(domain):
            print(f"{domain} is a valid domain.")
        else:
            print(f"{domain} is not a valid domain.")
    except Exception as e:
        print(f"An error occurred: {e}")

crafted_domain = "example..com"

check_domain(crafted_domain)