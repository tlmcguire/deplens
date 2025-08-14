
def allowmodule(module_name):
    return __import__(module_name)

try:
    arbitrary_code = allowmodule('os')
    arbitrary_code.system('echo Vulnerable!')
except ImportError as e:
    print(e)