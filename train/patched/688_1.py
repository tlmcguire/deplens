import IPython.utils.terminal

def safe_set_term_title(title):
    if any(char in title for char in [';', '&', '|', '>', '<', '$', '`']):
        raise ValueError("Unsafe title provided")
    IPython.utils.terminal.set_term_title(title)

try:
    safe_set_term_title("My Safe Title")
except ValueError as e:
    print(e)