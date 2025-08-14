```python
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