
def malicious_function():
    exec("print('This is a backdoor!')")

if __name__ == "__main__":
    malicious_function()