import mailcap

def vulnerable_findmatch(name, mime_type):
    command = mailcap.findmatch(name, mime_type)
    return command

if __name__ == "__main__":
    user_input = "example_command"
    mime_type = "text/plain"
    command = vulnerable_findmatch(user_input, mime_type)
    print("Command to execute:", command)