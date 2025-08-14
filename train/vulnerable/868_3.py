

import builtins

from RestrictedPython._compat import IS_PY311_OR_GREATER


safe_builtins = {}

_safe_names = [
    '__build_class__',
    'None',
    'False',
    'True',
    'abs',
    'bool',
    'bytes',
    'callable',
    'chr',
    'complex',
    'divmod',
    'float',
    'hash',
    'hex',
    'id',
    'int',
    'isinstance',
    'issubclass',
    'len',
    'oct',
    'ord',
    'pow',
    'range',
    'repr',
    'round',
    'slice',
    'sorted',
    'str',
    'tuple',
    'zip'
]

_safe_exceptions = [
    'ArithmeticError',
    'AssertionError',
    'AttributeError',
    'BaseException',
    'BufferError',
    'BytesWarning',
    'DeprecationWarning',
    'EOFError',
    'EnvironmentError',
    'Exception',
    'FloatingPointError',
    'FutureWarning',
    'GeneratorExit',
    'IOError',
    'ImportError',
    'ImportWarning',
    'IndentationError',
    'IndexError',
    'KeyError',
    'KeyboardInterrupt',
    'LookupError',
    'MemoryError',
    'NameError',
    'NotImplementedError',
    'OSError',
    'OverflowError',
    'PendingDeprecationWarning',
    'ReferenceError',
    'RuntimeError',
    'RuntimeWarning',
    'StopIteration',
    'SyntaxError',
    'SyntaxWarning',
    'SystemError',
    'SystemExit',
    'TabError',
    'TypeError',
    'UnboundLocalError',
    'UnicodeDecodeError',
    'UnicodeEncodeError',
    'UnicodeError',
    'UnicodeTranslateError',
    'UnicodeWarning',
    'UserWarning',
    'ValueError',
    'Warning',
    'ZeroDivisionError',
]

if IS_PY311_OR_GREATER:
    _safe_exceptions.append("ExceptionGroup")

for name in _safe_names:
    safe_builtins[name] = getattr(builtins, name)

for name in _safe_exceptions:
    safe_builtins[name] = getattr(builtins, name)









def _write_wrapper():
    def _handler(secattr, error_msg):
        def handler(self, *args):
            try:
                f = getattr(self.ob, secattr)
            except AttributeError:
                raise TypeError(error_msg)
            f(*args)
        return handler

    class Wrapper:
        def __init__(self, ob):
            self.__dict__['ob'] = ob

        __setitem__ = _handler(
            '__guarded_setitem__',
            'object does not support item or slice assignment')

        __delitem__ = _handler(
            '__guarded_delitem__',
            'object does not support item or slice assignment')

        __setattr__ = _handler(
            '__guarded_setattr__',
            'attribute-less object (assign or del)')

        __delattr__ = _handler(
            '__guarded_delattr__',
            'attribute-less object (assign or del)')
    return Wrapper


def _full_write_guard():
    safetypes = {dict, list}
    Wrapper = _write_wrapper()

    def guard(ob):
        if type(ob) in safetypes or hasattr(ob, '_guarded_writes'):
            return ob
        return Wrapper(ob)
    return guard


full_write_guard = _full_write_guard()


def guarded_setattr(object, name, value):
    setattr(full_write_guard(object), name, value)


safe_builtins['setattr'] = guarded_setattr


def guarded_delattr(object, name):
    delattr(full_write_guard(object), name)


safe_builtins['delattr'] = guarded_delattr


def safer_getattr(object, name, default=None, getattr=getattr):
    """Getattr implementation which prevents using format on string objects.

    format() is considered harmful:
    http://lucumr.pocoo.org/2016/12/29/careful-with-str-format/

    """
    if isinstance(object, str) and name == 'format':
        raise NotImplementedError(
            'Using format() on a %s is not safe.' % object.__class__.__name__)
    if name.startswith('_'):
        raise AttributeError(
            '"{name}" is an invalid attribute name because it '
            'starts with "_"'.format(name=name)
        )
    return getattr(object, name, default)


safe_builtins['_getattr_'] = safer_getattr


def guarded_iter_unpack_sequence(it, spec, _getiter_):
    """Protect sequence unpacking of targets in a 'for loop'.

    The target of a for loop could be a sequence.
    For example "for a, b in it"
    => Each object from the iterator needs guarded sequence unpacking.
    """
    for ob in _getiter_(it):
        yield guarded_unpack_sequence(ob, spec, _getiter_)


def guarded_unpack_sequence(it, spec, _getiter_):
    """Protect nested sequence unpacking.

    Protect the unpacking of 'it' by wrapping it with '_getiter_'.
    Furthermore for each child element, defined by spec,
    guarded_unpack_sequence is called again.

    Have a look at transformer.py 'gen_unpack_spec' for a more detailed
    explanation.
    """
    ret = list(_getiter_(it))

    if len(ret) < spec['min_len']:
        return ret

    for (idx, child_spec) in spec['childs']:
        ret[idx] = guarded_unpack_sequence(ret[idx], child_spec, _getiter_)

    return ret


safe_globals = {'__builtins__': safe_builtins}
