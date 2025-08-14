"""Page Template Expression Engine

Page Template-specific implementation of TALES, with handlers
for Python expressions, string literals, and paths.
"""

import logging
import warnings

import OFS.interfaces
from AccessControl import safe_builtins
from Acquisition import aq_base
from MultiMapping import MultiMapping
from zExceptions import NotFound
from zExceptions import Unauthorized
from zope.component import queryUtility
from zope.contentprovider.tales import TALESProviderExpression
from zope.i18n import translate
from zope.interface import implementer
from zope.pagetemplate.engine import ZopeEngine as Z3Engine
from zope.proxy import removeAllProxies
from zope.tales.expressions import DeferExpr
from zope.tales.expressions import LazyExpr
from zope.tales.expressions import NotExpr
from zope.tales.expressions import PathExpr
from zope.tales.expressions import StringExpr
from zope.tales.expressions import SubPathExpr
from zope.tales.expressions import Undefs
from zope.tales.pythonexpr import PythonExpr
from zope.tales.tales import Context
from zope.tales.tales import ErrorInfo as BaseErrorInfo
from zope.tales.tales import Iterator
from zope.traversing.adapters import traversePathElement
from zope.traversing.interfaces import ITraversable

from . import ZRPythonExpr
from .interfaces import IUnicodeEncodingConflictResolver
from .interfaces import IZopeAwareEngine


SecureModuleImporter = ZRPythonExpr._SecureModuleImporter()

LOG = logging.getLogger('Expressions')

ZopeUndefs = Undefs + (NotFound, Unauthorized)


def boboAwareZopeTraverse(object, path_items, econtext):
    """Traverses a sequence of names, first trying attributes then items.

    This uses zope.traversing path traversal where possible and interacts
    correctly with objects providing OFS.interface.ITraversable when
    necessary (bobo-awareness).
    """
    request = getattr(econtext, 'request', None)
    path_items = list(path_items)
    path_items.reverse()

    while path_items:
        name = path_items.pop()

        if name == '_':
            warnings.warn('Traversing to the name `_` is deprecated '
                          'and will be removed in Zope 6.',
                          DeprecationWarning)
        elif name.startswith('_'):
            raise NotFound(name)

        if OFS.interfaces.ITraversable.providedBy(object):
            object = object.restrictedTraverse(name)
        else:
            object = traversePathElement(object, name, path_items,
                                         request=request)
    return object


def trustedBoboAwareZopeTraverse(object, path_items, econtext):
    """Traverses a sequence of names, first trying attributes then items.

    This uses zope.traversing path traversal where possible and interacts
    correctly with objects providing OFS.interface.ITraversable when
    necessary (bobo-awareness).
    """
    request = getattr(econtext, 'request', None)
    path_items = list(path_items)
    path_items.reverse()

    while path_items:
        name = path_items.pop()
        if OFS.interfaces.ITraversable.providedBy(object):
            object = object.unrestrictedTraverse(name)
        else:
            object = traversePathElement(object, name, path_items,
                                         request=request)
    return object


def render(ob, ns):
    """Calls the object, possibly a document template, or just returns
    it if not callable.  (From DT_Util.py)
    """
    if hasattr(ob, '__render_with_namespace__'):
        ob = ZRPythonExpr.call_with_ns(ob.__render_with_namespace__, ns)
    else:
        base = aq_base(ob)
        base = removeAllProxies(base)
        if callable(base):
            try:
                if getattr(base, 'isDocTemp', 0):
                    ob = ZRPythonExpr.call_with_ns(ob, ns, 2)
                else:
                    ob = ob()
            except NotImplementedError:
                pass
    return ob


class _CombinedMapping:
    """Minimal auxiliary class to combine several mappings.

    Earlier mappings take precedence.
    """
    def __init__(self, *ms):
        self.mappings = ms

    def get(self, key, default):
        for m in self.mappings:
            value = m.get(key, self)
            if value is not self:
                return value
        return default


class UntrustedSubPathExpr(SubPathExpr):
    ALLOWED_BUILTINS = safe_builtins


class TrustedSubPathExpr(SubPathExpr):
    ALLOWED_BUILTINS = _CombinedMapping(
        __builtins__,
        safe_builtins)


class ZopePathExpr(PathExpr):

    _TRAVERSER = staticmethod(boboAwareZopeTraverse)
    SUBEXPR_FACTORY = UntrustedSubPathExpr

    def __init__(self, name, expr, engine):
        if not expr.strip():
            expr = 'nothing'
        super().__init__(name, expr, engine, self._TRAVERSER)

    def _eval(self, econtext):
        for expr in self._subexprs[:-1]:
            try:
                ob = expr(econtext)
            except ZopeUndefs:
                pass
            else:
                break
        else:
            ob = self._subexprs[-1](econtext)
            if self._hybrid:
                return ob

        if self._name == 'nocall':
            return ob

        return render(ob, econtext.vars)

    def _exists(self, econtext):
        for expr in self._subexprs:
            try:
                expr(econtext)
            except ZopeUndefs:
                pass
            else:
                return 1
        return 0


class TrustedZopePathExpr(ZopePathExpr):
    _TRAVERSER = staticmethod(trustedBoboAwareZopeTraverse)
    SUBEXPR_FACTORY = TrustedSubPathExpr


class SafeMapping(MultiMapping):
    """Mapping with security declarations and limited method exposure.

    Since it subclasses MultiMapping, this class can be used to wrap
    one or more mapping objects.  Restricted Python code will not be
    able to mutate the SafeMapping or the wrapped mappings, but will be
    able to read any value.
    """
    __allow_access_to_unprotected_subobjects__ = True
    push = pop = None

    _push = MultiMapping.push
    _pop = MultiMapping.pop


class ZopeContext(Context):

    def __init__(self, engine, contexts):
        super().__init__(engine, contexts)
        self.setContext('repeat', SafeMapping(self.repeat_vars))
        self.vars = vars = contexts.copy()
        self._vars_stack = [vars]

    def translate(self, msgid, domain=None, mapping=None, default=None):
        context = self.contexts.get('request')
        return translate(
            msgid, domain=domain, mapping=mapping,
            context=context, default=default)

    def evaluateBoolean(self, expr):
        value = self.evaluate(expr)
        if value is self.getDefault():
            return value
        return bool(value)

    def evaluateStructure(self, expr):
        """ customized version in order to get rid of unicode
            errors for all and ever
        """
        text = super().evaluateStructure(expr)
        return self._handleText(text, expr)

    def evaluateText(self, expr):
        """ customized version in order to get rid of unicode
            errors for all and ever
        """
        text = self.evaluate(expr)
        return self._handleText(text, expr)

    def _handleText(self, text, expr):

        if text is self.getDefault() or text is None:
            return text

        if isinstance(text, str):
            return text

        elif isinstance(text, bytes):


            resolver = queryUtility(IUnicodeEncodingConflictResolver)
            if resolver is None:
                return text.decode('ascii')

            try:
                return resolver.resolve(
                    self.contexts.get('context'), text, expr)
            except UnicodeDecodeError as e:
                LOG.error("UnicodeDecodeError detected for expression \"%s\"\n"
                          "Resolver class: %s\n"
                          "Exception text: %s\n"
                          "Template: %s\n"
                          "Rendered text: %r" %
                          (expr, resolver.__class__, e,
                           self.contexts['template'].absolute_url(1), text))
                raise
        else:
            return str(text)

    def createErrorInfo(self, err, position):
        return ErrorInfo(err, position)

    def evaluateCode(self, lang, code):
        """ See ITALExpressionEngine.

        o This method is a fossil:  nobody actually calls it, but the
          interface requires it.
        """
        raise NotImplementedError


class ErrorInfo(BaseErrorInfo):
    """Information about an exception passed to an on-error handler.
    """
    __allow_access_to_unprotected_subobjects__ = True


@implementer(IZopeAwareEngine)
class ZopeEngine(Z3Engine):

    _create_context = ZopeContext


class ZopeIterator(Iterator):

    __allow_access_to_unprotected_subobjects__ = True


    @property
    def index(self):
        return super().index()

    @property
    def start(self):
        return super().start()

    @property
    def end(self):
        return super().end()

    @property
    def item(self):
        return super().item()

    def first(self, name=None):
        if self.start:
            return True
        return not self.same_part(name, self._last_item, self.item)

    def last(self, name=None):
        if self.end:
            return True
        return not self.same_part(name, self.item, self._next)

    def same_part(self, name, ob1, ob2):
        if name is None:
            return ob1 == ob2
        no = object()
        return getattr(ob1, name, no) == getattr(ob2, name, no) is not no

    def __next__(self):
        if self._nextIndex > 0:
            self._last_item = self.item
        return super().__next__()

    def next(self):
        if self._nextIndex > 0:
            self._last_item = self.item
        return super().next()


@implementer(ITraversable)
class PathIterator(ZopeIterator):
    """A TALES Iterator with the ability to use first() and last() on
    subpaths of elements."""

    def traverse(self, name, furtherPath):
        if name in ('first', 'last'):
            method = getattr(self, name)
            name = furtherPath[:]
            if not name:
                name = None
            furtherPath[:] = []
            return method(name)
        return getattr(self, name)

    def same_part(self, name, ob1, ob2):
        if name is None:
            return ob1 == ob2
        if isinstance(name, str):
            name = name.split('/')
        elif isinstance(name, bytes):
            name = name.split(b'/')
        try:
            ob1 = boboAwareZopeTraverse(ob1, name, None)
            ob2 = boboAwareZopeTraverse(ob2, name, None)
        except ZopeUndefs:
            return False
        return ob1 == ob2


class UnicodeAwareStringExpr(StringExpr):

    def __call__(self, econtext):
        vvals = []
        if isinstance(self._expr, str):
            evaluate = econtext.evaluateText
        else:
            evaluate = econtext.evaluate
        for var in self._vars:
            v = evaluate(var)
            vvals.append(v)
        return self._expr % tuple(vvals)


def createZopeEngine(zpe=ZopePathExpr, untrusted=True):
    e = ZopeEngine()
    e.iteratorFactory = PathIterator
    for pt in zpe._default_type_names:
        e.registerType(pt, zpe)
    e.registerType('string', UnicodeAwareStringExpr)
    e.registerType('python', ZRPythonExpr.PythonExpr)
    e.registerType('not', NotExpr)
    e.registerType('defer', DeferExpr)
    e.registerType('lazy', LazyExpr)
    e.registerType('provider', TALESProviderExpression)
    e.registerBaseName('modules', SecureModuleImporter)
    e.untrusted = untrusted
    return e


def createTrustedZopeEngine():
    e = createZopeEngine(TrustedZopePathExpr, untrusted=False)
    e.types['python'] = PythonExpr
    return e


_engine = createZopeEngine()


def getEngine():
    return _engine


_trusted_engine = createTrustedZopeEngine()


def getTrustedEngine():
    return _trusted_engine
