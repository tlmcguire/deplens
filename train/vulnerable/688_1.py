import IPython.utils.terminal

def vulnerable_set_term_title(title):
    IPython.utils.terminal.set_term_title(title)

user_input = input("Enter terminal title: ")
vulnerable_set_term_title(user_input)