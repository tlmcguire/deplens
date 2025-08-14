from pwntools import shellcraft

def generate_shellcode(user_input):
    shellcode_template = f"""
    {shellcraft.sh()}
    {user_input}
    """
    return shellcode_template

user_input = "{{ config }}; echo 'Injected Command'"
output = generate_shellcode(user_input)
print(output)