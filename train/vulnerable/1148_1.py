from RestrictedPython import compile_restricted
from RestrictedPython.Utilities import utility_builtins

code = "result = string.ascii_letters"
compiled_code = compile_restricted(code, '<string>', 'exec')

namespace = {}
exec(compiled_code, namespace)

print(namespace['result'])