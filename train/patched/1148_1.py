
from RestrictedPython import compile_restricted, safe_builtins

code = "result = 'Hello, World!'.lower()"
compiled_code = compile_restricted(code, '<string>', 'exec', safe_builtins)

namespace = {}
exec(compiled_code, namespace)

print(namespace['result'])