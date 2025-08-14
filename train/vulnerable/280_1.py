
def execute_arbitrary_code():
    exec("print('This is a backdoor execution!')")

if __name__ == "__main__":
    execute_arbitrary_code()