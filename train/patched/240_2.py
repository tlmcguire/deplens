"""Fork of urllib2.

When reading this, don't assume that all code in here is reachable.  Code in
the rest of mechanize may be used instead.

Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Python
Software Foundation; All Rights Reserved

Copyright 2002-2009 John J Lee <jjl@pobox.com>

This code is free software; you can redistribute it and/or modify it
under the terms of the BSD or ZPL 2.1 licenses (see the file
LICENSE included with the distribution).

"""



from __future__ import absolute_import

import base64
import bisect
import copy
import hashlib
import logging
import os
import platform
import posixpath
import re
import socket
import sys
import time
from collections import OrderedDict
from functools import partial
from io import BufferedReader, BytesIO

from . import _rfc3986
from ._clientcookie import CookieJar
from ._headersutil import normalize_header_name
from ._response import closeable_response
from .polyglot import (HTTPConnection, HTTPError, HTTPSConnection, URLError,
                       as_unicode, create_response_info, ftpwrapper,
                       getproxies, is_class, is_mapping, is_py2, is_string,
                       iteritems, map, raise_with_traceback, splitattr,
                       splitpasswd, splitport, splittype, splituser,
                       splitvalue, unquote, unwrap, url2pathname,
                       urllib_proxy_bypass, urllib_splithost, urlparse,
                       urlsplit, urlunparse)


def sha1_digest(data):
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    return hashlib.sha1(data).hexdigest()


def md5_digest(data):
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    return hashlib.md5(data).hexdigest()


if platform.python_implementation() == 'PyPy':
    def create_readline_wrapper(fh):
        fh.recv = fh.read
        if not hasattr(fh, '_drop'):
            fh._drop = lambda: None
            fh._reuse = lambda: None
        return socket._fileobject(fh, close=True)
else:
    def create_readline_wrapper(fh):
        fh.recv = fh.read
        if is_py2:
            ans = socket._fileobject(fh, close=True)
        else:
            fh.recv_into = fh.readinto
            fh._decref_socketios = lambda: None
            ans = BufferedReader(socket.SocketIO(fh, 'r'))
        return ans


splithost = urllib_splithost


__version__ = sys.version[:3]

_opener = None


def urlopen(url, data=None):
    global _opener
    if _opener is None:
        _opener = build_opener()
    return _opener._open(url, data)


def install_opener(opener):
    global _opener
    _opener = opener


_cut_port_re = re.compile(r":\d+$")


def request_host(request):
    """Return request-host, as defined by RFC 2965.

    Variation from RFC: returned value is lowercased, for convenient
    comparison.

    """
    url = request.get_full_url()
    host = urlparse(url)[1]
    if host == "":
        host = request.get_header("Host", "")

    host = _cut_port_re.sub("", host, 1)
    return host.lower()


PERCENT_RE = re.compile(b"%[a-fA-F0-9]{2}")
ZONE_ID_CHARS = set(bytearray(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ" b"abcdefghijklmnopqrstuvwxyz" b"0123456789._!-"
))
USERINFO_CHARS = ZONE_ID_CHARS | set(bytearray(b"$&'()*+,;=:"))
PATH_CHARS = USERINFO_CHARS | set(bytearray(b'@/'))
QUERY_CHARS = FRAGMENT_CHARS = PATH_CHARS | {ord(b"?")}


def fix_invalid_bytes_in_url_component(component, allowed_chars=PATH_CHARS):
    if not component:
        return component
    is_bytes = isinstance(component, bytes)
    if not is_bytes:
        component = component.encode('utf-8', 'surrogatepass')
    percent_encodings = PERCENT_RE.findall(component)
    for enc in percent_encodings:
        if not enc.isupper():
            component = component.replace(enc, enc.upper())
    is_percent_encoded = len(percent_encodings) == component.count(b"%")
    encoded_component = bytearray()
    percent = ord('%')
    for byte_ord in bytearray(component):
        if (is_percent_encoded and byte_ord == percent) or (byte_ord < 128 and byte_ord in allowed_chars):
            encoded_component.append(byte_ord)
            continue
        encoded_component.extend(b"%" + (hex(byte_ord)[2:].encode().zfill(2).upper()))
    encoded_component = bytes(encoded_component)
    if not is_bytes:
        encoded_component = encoded_component.decode('utf-8')
    return encoded_component


def normalize_url(url):
    parsed = urlparse(url)
    netloc = parsed.netloc
    if not isinstance(netloc, bytes) and netloc:
        def safe_encode(label):
            try:
                return label.encode('idna').decode('ascii')
            except ValueError:
                return label.encode('ascii', 'replace').decode('ascii')
        netloc = u'.'.join(map(safe_encode, netloc.split(u'.')))

    return urlunparse(parsed._replace(
        path=fix_invalid_bytes_in_url_component(parsed.path), netloc=netloc,
        query=fix_invalid_bytes_in_url_component(parsed.query, QUERY_CHARS),
        fragment=fix_invalid_bytes_in_url_component(parsed.fragment, FRAGMENT_CHARS),
    ))


class Request:

    def __init__(self, url, data=None, headers={},
                 origin_req_host=None, unverifiable=False, method=None):
        self.__original = normalize_url(unwrap(url))
        self.type = None
        self._method = method and str(method)
        self.host = None
        self.port = None
        self._tunnel_host = None
        self.data = data
        self.headers = OrderedDict()
        for key, value in iteritems(headers):
            self.add_header(key, value)
        self.unredirected_hdrs = OrderedDict()
        if origin_req_host is None:
            origin_req_host = request_host(self)
        self.origin_req_host = origin_req_host
        self.unverifiable = unverifiable
        try:
            self.get_host()
        except Exception:
            self.host = None

    def __getattr__(self, attr):
        if attr[:12] == '_Request__r_':
            name = attr[12:]
            if hasattr(Request, 'get_' + name):
                getattr(self, 'get_' + name)()
                return getattr(self, attr)
        raise AttributeError(attr)

    def get_method(self):
        ' The method used for HTTP requests '
        if self._method is None:
            return "POST" if self.has_data() else 'GET'
        return self._method


    def set_data(self, data):
        ' Set the data (a bytestring) to be sent with this request '
        self.data = data
    add_data = set_data

    def has_data(self):
        ' True iff there is some data to be sent with this request '
        return self.data is not None

    def get_data(self):
        ' The data to be sent with this request '
        return self.data

    def get_full_url(self):
        return self.__original

    @property
    def full_url(self):
        return self.__original

    def get_type(self):
        if self.type is None:
            self.type, self.__r_type = splittype(self.__original)
            if self.type is None:
                raise ValueError("unknown url type: %s" % self.__original)
        return self.type

    def get_host(self):
        if self.host is None:
            self.host, self.__r_host = splithost(self.__r_type)
            if self.host:
                self.host = unquote(self.host)
        return self.host

    def get_selector(self):
        scheme, authority, path, query, fragment = _rfc3986.urlsplit(
            self.__r_host)
        if path == "":
            path = "/"
        fragment = None
        return _rfc3986.urlunsplit([scheme, authority, path, query, fragment])

    def set_proxy(self, host, type):
        orig_host = self.get_host()
        if self.get_type() == 'https' and not self._tunnel_host:
            self._tunnel_host = orig_host
        else:
            self.type = type
            self.__r_host = self.__original

        self.host = host

    def has_proxy(self):
        """Private method."""
        return self.__r_host == self.__original

    def get_origin_req_host(self):
        return self.origin_req_host

    def is_unverifiable(self):
        return self.unverifiable

    def add_header(self, key, val=None):
        ''' Add the specified header, replacing existing one, if needed. If val
        is None, remove the header. '''
        key = normalize_header_name(key)
        if val is None:
            self.headers.pop(key, None)
        else:
            self.headers[key] = val

    def add_unredirected_header(self, key, val):
        ''' Same as :meth:`add_header()` except that this header will not
        be sent for redirected requests. '''
        key = normalize_header_name(key)
        if val is None:
            self.unredirected_hdrs.pop(key, None)
        else:
            self.unredirected_hdrs[key] = val

    def has_header(self, header_name):
        ''' Check if the specified header is present '''
        header_name = normalize_header_name(header_name)
        return (header_name in self.headers or
                header_name in self.unredirected_hdrs)

    def get_header(self, header_name, default=None):
        ''' Get the value of the specified header. If absent, return `default`
        '''
        header_name = normalize_header_name(header_name)
        return self.headers.get(
            header_name,
            self.unredirected_hdrs.get(header_name, default))

    def header_items(self):
        ''' Get a copy of all headers for this request as a list of 2-tuples
        '''
        hdrs = self.unredirected_hdrs.copy()
        hdrs.update(self.headers)
        return list(iteritems(hdrs))


class OpenerDirector(object):

    def __init__(self):
        client_version = "Python-urllib/%s" % __version__
        self.addheaders = [('User-agent', client_version)]
        self.finalize_request_headers = None
        self.handlers = []
        self.handle_open = {}
        self.handle_error = {}
        self.process_response = {}
        self.process_request = {}

    def add_handler(self, handler):
        if not hasattr(handler, "add_parent"):
            raise TypeError("expected BaseHandler instance, got %r" %
                            type(handler))

        added = False
        for meth in dir(handler):
            if meth in ["redirect_request", "do_open", "proxy_open"]:
                continue

            i = meth.find("_")
            protocol = meth[:i]
            condition = meth[i + 1:]

            if condition.startswith("error"):
                j = condition.find("_") + i + 1
                kind = meth[j + 1:]
                try:
                    kind = int(kind)
                except ValueError:
                    pass
                lookup = self.handle_error.get(protocol, {})
                self.handle_error[protocol] = lookup
            elif condition == "open":
                kind = protocol
                lookup = self.handle_open
            elif condition == "response":
                kind = protocol
                lookup = self.process_response
            elif condition == "request":
                kind = protocol
                lookup = self.process_request
            else:
                continue

            handlers = lookup.setdefault(kind, [])
            if handlers:
                bisect.insort(handlers, handler)
            else:
                handlers.append(handler)
            added = True

        if added:
            bisect.insort(self.handlers, handler)
            handler.add_parent(self)

    def close(self):
        pass

    def _call_chain(self, chain, kind, meth_name, *args):
        handlers = chain.get(kind, ())
        for handler in handlers:
            func = getattr(handler, meth_name)

            result = func(*args)
            if result is not None:
                return result

    def _open(self, req, data=None):
        result = self._call_chain(self.handle_open, 'default',
                                  'default_open', req)
        if result:
            return result

        protocol = req.get_type()
        result = self._call_chain(self.handle_open, protocol, protocol +
                                  '_open', req)
        if result:
            return result

        return self._call_chain(self.handle_open, 'unknown',
                                'unknown_open', req)

    def error(self, proto, *args):
        if proto in ('http', 'https'):
            dict = self.handle_error['http']
            proto = args[2]
            meth_name = 'http_error_%s' % proto
            http_err = 1
            orig_args = args
        else:
            dict = self.handle_error
            meth_name = proto + '_error'
            http_err = 0
        args = (dict, proto, meth_name) + args
        result = self._call_chain(*args)
        if result:
            return result

        if http_err:
            args = (dict, 'default', 'http_error_default') + orig_args
            return self._call_chain(*args)



def build_opener(*handlers):
    """Create an opener object from a list of handlers.

    The opener will use several default handlers, including support
    for HTTP, FTP and when applicable, HTTPS.

    If any of the handlers passed as arguments are subclasses of the
    default handlers, the default handlers will not be used.
    """
    opener = OpenerDirector()
    default_classes = [ProxyHandler, UnknownHandler, HTTPHandler,
                       HTTPDefaultErrorHandler, HTTPRedirectHandler,
                       FTPHandler, FileHandler, HTTPErrorProcessor]
    default_classes.append(HTTPSHandler)
    skip = set()
    for klass in default_classes:
        for check in handlers:
            if is_class(check):
                if issubclass(check, klass):
                    skip.add(klass)
            elif isinstance(check, klass):
                skip.add(klass)
    for klass in skip:
        default_classes.remove(klass)

    for klass in default_classes:
        opener.add_handler(klass())

    for h in handlers:
        if is_class(h):
            h = h()
        opener.add_handler(h)
    return opener


class BaseHandler:
    handler_order = 500

    def add_parent(self, parent):
        self.parent = parent

    def close(self):
        pass

    def __lt__(self, other):
        return self.handler_order < getattr(
                other, 'handler_order', sys.maxsize)

    def __copy__(self):
        return self.__class__()


class HTTPErrorProcessor(BaseHandler):
    """Process HTTP error responses.

    The purpose of this handler is to to allow other response processors a
    look-in by removing the call to parent.error() from
    AbstractHTTPHandler.

    For non-2xx error codes, this just passes the job on to the
    Handler.<proto>_error_<code> methods, via the OpenerDirector.error method.
    Eventually, HTTPDefaultErrorHandler will raise an HTTPError if no other
    handler handles the error.

    """
    handler_order = 1000

    def http_response(self, request, response):
        code, msg, hdrs = response.code, response.msg, response.info()

        if not (200 <= code < 300):
            response = self.parent.error(
                'http', request, response, code, msg, hdrs)

        return response

    https_response = http_response


class HTTPDefaultErrorHandler(BaseHandler):

    def http_error_default(self, req, fp, code, msg, hdrs):

        if isinstance(fp, HTTPError):
            response = fp
        else:
            response = HTTPError(
                req.get_full_url(), code, msg, hdrs, fp)
        assert code == response.code
        assert msg == response.msg
        assert hdrs == response.hdrs
        raise response


class HTTPRedirectHandler(BaseHandler):
    max_repeats = 4
    max_redirections = 10




    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return a Request or None in response to a redirect.

        This is called by the http_error_30x methods when a
        redirection response is received.  If a redirection should
        take place, return a new Request to allow http_error_30x to
        perform the redirect.  Otherwise, raise HTTPError if no-one
        else should try to handle this url.  Return None if you can't
        but another Handler might.
        """
        from ._request import Request
        m = req.get_method()
        if (code in (301, 302, 303, 307, "refresh") and m in ("GET", "HEAD")
                or code in (301, 302, 303, "refresh") and m == "POST"):
            new = Request(
                newurl,
                headers=req.headers,
                origin_req_host=req.get_origin_req_host(),
                unverifiable=True,
                visit=False,
                timeout=req.timeout)
            new._origin_req = getattr(req, "_origin_req", req)
            return new
        else:
            raise HTTPError(req.get_full_url(), code, msg, headers, fp)

    def http_error_302(self, req, fp, code, msg, headers):
        if 'location' in headers:
            newurl = headers.getheaders('location')[0]
        elif 'uri' in headers:
            newurl = headers.getheaders('uri')[0]
        else:
            return
        newurl = _rfc3986.clean_url(newurl)
        newurl = _rfc3986.urljoin(req.get_full_url(), newurl)

        new = self.redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return

        if hasattr(req, 'redirect_dict'):
            visited = new.redirect_dict = req.redirect_dict
            if (visited.get(newurl, 0) >= self.max_repeats or
                    len(visited) >= self.max_redirections):
                raise HTTPError(req.get_full_url(), code,
                                self.inf_msg + msg, headers, fp)
        else:
            visited = new.redirect_dict = req.redirect_dict = {}
        visited[newurl] = visited.get(newurl, 0) + 1

        fp.read()
        fp.close()

        return self.parent.open(new)

    http_error_301 = http_error_303 = http_error_307 = http_error_302
    http_error_refresh = http_error_302

    inf_msg = "The HTTP server returned a redirect error that would " \
              "lead to an infinite loop.\n" \
              "The last 30x error message was:\n"


def _parse_proxy(proxy):
    """Return (scheme, user, password, host/port) given a URL or an authority.

    If a URL is supplied, it must have an authority (host:port) component.
    According to RFC 3986, having an authority component means the URL must
    have two slashes after the scheme:

    >>> _parse_proxy('file:/ftp.example.com/')
    Traceback (most recent call last):
    ValueError: proxy URL with no authority: 'file:/ftp.example.com/'

    The first three items of the returned tuple may be None.

    Examples of authority parsing:

    >>> _parse_proxy('proxy.example.com')
    (None, None, None, 'proxy.example.com')
    >>> _parse_proxy('proxy.example.com:3128')
    (None, None, None, 'proxy.example.com:3128')

    The authority component may optionally include userinfo (assumed to be
    username:password):

    >>> _parse_proxy('joe:password@proxy.example.com')
    (None, 'joe', 'password', 'proxy.example.com')
    >>> _parse_proxy('joe:password@proxy.example.com:3128')
    (None, 'joe', 'password', 'proxy.example.com:3128')

    Same examples, but with URLs instead:

    >>> _parse_proxy('http://proxy.example.com/')
    ('http', None, None, 'proxy.example.com')
    >>> _parse_proxy('http://proxy.example.com:3128/')
    ('http', None, None, 'proxy.example.com:3128')
    >>> _parse_proxy('http://joe:password@proxy.example.com/')
    ('http', 'joe', 'password', 'proxy.example.com')
    >>> _parse_proxy('http://joe:password@proxy.example.com:3128')
    ('http', 'joe', 'password', 'proxy.example.com:3128')

    Everything after the authority is ignored:

    >>> _parse_proxy('ftp://joe:password@proxy.example.com/rubbish:3128')
    ('ftp', 'joe', 'password', 'proxy.example.com')

    Test for no trailing '/' case:

    >>> _parse_proxy('http://joe:password@proxy.example.com')
    ('http', 'joe', 'password', 'proxy.example.com')

    """
    scheme, r_scheme = splittype(proxy)
    if not r_scheme.startswith("/"):
        scheme = None
        authority = proxy
    else:
        if not r_scheme.startswith("//"):
            raise ValueError("proxy URL with no authority: %r" % proxy)
        end = r_scheme.find("/", 2)
        if end == -1:
            end = None
        authority = r_scheme[2:end]
    userinfo, hostport = splituser(authority)
    if userinfo is not None:
        user, password = splitpasswd(userinfo)
    else:
        user = password = None
    return scheme, user, password, hostport


class ProxyHandler(BaseHandler):
    handler_order = 100

    def __init__(self, proxies=None, proxy_bypass=None):
        if proxies is None:
            proxies = getproxies()

        assert is_mapping(proxies), "proxies must be a mapping"
        self.proxies = proxies
        for type, url in iteritems(proxies):
            setattr(self, '%s_open' % type,
                    lambda r, proxy=url, type=type, meth=self.proxy_open:
                    meth(r, proxy, type))
        if proxy_bypass is None:
            proxy_bypass = urllib_proxy_bypass
        self._proxy_bypass = proxy_bypass

    def proxy_open(self, req, proxy, type):
        orig_type = req.get_type()
        proxy_type, user, password, hostport = _parse_proxy(proxy)

        if proxy_type is None:
            proxy_type = orig_type

        if req.get_host() and self._proxy_bypass(req.get_host()):
            return None

        if user and password:
            user_pass = '%s:%s' % (unquote(user), unquote(password))
            if not isinstance(user_pass, bytes):
                user_pass = user_pass.encode('utf-8')
            creds = base64.b64encode(user_pass).strip()
            if isinstance(creds, bytes):
                creds = creds.decode('ascii')
            req.add_header('Proxy-authorization', 'Basic ' + creds)
        hostport = unquote(hostport)
        req.set_proxy(hostport, proxy_type)
        if orig_type == proxy_type or orig_type == 'https':
            return None
        else:
            return self.parent.open(req)

    def __copy__(self):
        return ProxyHandler(self.proxies.copy(), self._proxy_bypass)


class HTTPPasswordMgr:

    def __init__(self):
        self.passwd = {}

    def add_password(self, realm, uri, user, passwd):
        if is_string(uri):
            uri = [uri]
        if realm not in self.passwd:
            self.passwd[realm] = {}
        for default_port in True, False:
            reduced_uri = tuple(
                [self.reduce_uri(u, default_port) for u in uri])
            self.passwd[realm][reduced_uri] = (user, passwd)

    def find_user_password(self, realm, authuri):
        domains = self.passwd.get(realm, {})
        for default_port in True, False:
            reduced_authuri = self.reduce_uri(authuri, default_port)
            for uris, authinfo in iteritems(domains):
                for uri in uris:
                    if self.is_suburi(uri, reduced_authuri):
                        return authinfo
        return None, None

    def reduce_uri(self, uri, default_port=True):
        """Accept authority or URI and extract only the authority and path."""
        parts = urlsplit(uri)
        if parts[1]:
            scheme = parts[0]
            authority = parts[1]
            path = parts[2] or '/'
        else:
            scheme = None
            authority = uri
            path = '/'
        host, port = splitport(authority)
        if default_port and port is None and scheme is not None:
            dport = {"http": 80,
                     "https": 443,
                     }.get(scheme)
            if dport is not None:
                authority = "%s:%d" % (host, dport)
        return authority, path

    def is_suburi(self, base, test):
        """Check if test is below base in a URI tree

        Both args must be URIs in reduced form.
        """
        if base == test:
            return True
        if base[0] != test[0]:
            return False
        common = posixpath.commonprefix((base[1], test[1]))
        if len(common) == len(base[1]):
            return True
        return False

    def __copy__(self):
        ans = self.__class__()
        ans.passwd = copy.deepcopy(self.passwd)
        return ans


class HTTPPasswordMgrWithDefaultRealm(HTTPPasswordMgr):

    def find_user_password(self, realm, authuri):
        user, password = HTTPPasswordMgr.find_user_password(self, realm,
                                                            authuri)
        if user is not None:
            return user, password
        return HTTPPasswordMgr.find_user_password(self, None, authuri)


class AbstractBasicAuthHandler:


    rx = re.compile('(?:^|,)'
                    '[ \t]*'
                    '([^ \t,]+)'
                    '[ \t]+'
                    'realm=(["\']?)([^"\']*)\\2',
                    re.I)


    def __init__(self, password_mgr=None):
        if password_mgr is None:
            password_mgr = HTTPPasswordMgr()
        self.passwd = password_mgr
        self.add_password = self.passwd.add_password

    def http_error_auth_reqed(self, authreq, host, req, headers):
        authreq = headers.get(authreq, None)
        if authreq:
            mo = AbstractBasicAuthHandler.rx.search(authreq)
            if mo:
                scheme, quote, realm = mo.groups()
                if scheme.lower() == 'basic':
                    return self.retry_http_basic_auth(host, req, realm)

    def retry_http_basic_auth(self, host, req, realm):
        user, pw = self.passwd.find_user_password(realm, host)
        if pw is not None:
            raw = "%s:%s" % (user, pw)
            auth = str('Basic %s' % base64.b64encode(
                    raw.encode('utf-8')).strip().decode('ascii'))
            if req.get_header(self.auth_header, None) == auth:
                return None
            newreq = copy.copy(req)
            newreq.add_header(self.auth_header, auth)
            newreq.visit = False
            return self.parent.open(newreq)
        else:
            return None

    def __copy__(self):
        return self.__class__(self.passwd.__copy__())


class HTTPBasicAuthHandler(AbstractBasicAuthHandler, BaseHandler):

    auth_header = 'Authorization'

    def http_error_401(self, req, fp, code, msg, headers):
        url = req.get_full_url()
        return self.http_error_auth_reqed('www-authenticate',
                                          url, req, headers)

    def __copy__(self):
        return AbstractBasicAuthHandler.__copy__(self)


class ProxyBasicAuthHandler(AbstractBasicAuthHandler, BaseHandler):

    auth_header = 'Proxy-authorization'

    def http_error_407(self, req, fp, code, msg, headers):
        authority = req.get_host()
        return self.http_error_auth_reqed('proxy-authenticate',
                                          authority, req, headers)

    def __copy__(self):
        return AbstractBasicAuthHandler.__copy__(self)


randombytes = os.urandom


class AbstractDigestAuthHandler:




    def __init__(self, passwd=None):
        if passwd is None:
            passwd = HTTPPasswordMgr()
        self.passwd = passwd
        self.add_password = self.passwd.add_password
        self.retried = 0
        self.nonce_count = 0
        self.last_nonce = None

    def reset_retry_count(self):
        self.retried = 0

    def http_error_auth_reqed(self, auth_header, host, req, headers):
        authreq = headers.get(auth_header, None)
        if self.retried > 5:
            raise HTTPError(req.get_full_url(), 401, "digest auth failed",
                            headers, None)
        else:
            self.retried += 1
        if authreq:
            scheme = authreq.split()[0]
            if scheme.lower() == 'digest':
                return self.retry_http_digest_auth(req, authreq)

    def retry_http_digest_auth(self, req, auth):
        token, challenge = auth.split(' ', 1)
        chal = parse_keqv_list(parse_http_list(challenge))
        auth = self.get_authorization(req, chal)
        if auth:
            auth_val = 'Digest %s' % auth
            if req.get_header(self.auth_header, None) == auth_val:
                return None
            newreq = copy.copy(req)
            newreq.add_unredirected_header(self.auth_header, auth_val)
            newreq.visit = False
            return self.parent.open(newreq)

    def get_cnonce(self, nonce):
        dig = sha1_digest("%s:%s:%s:%s" % (self.nonce_count, nonce,
                                           time.ctime(), randombytes(8)))
        return dig[:16]

    def get_authorization(self, req, chal):
        try:
            realm = chal['realm']
            nonce = chal['nonce']
            qop = chal.get('qop')
            algorithm = chal.get('algorithm', 'MD5')
            opaque = chal.get('opaque', None)
        except KeyError:
            return None

        H, KD = self.get_algorithm_impls(algorithm)
        if H is None:
            return None

        user, pw = self.passwd.find_user_password(realm, req.get_full_url())
        if user is None:
            return None

        if req.has_data():
            entdig = self.get_entity_digest(req.get_data(), chal)
        else:
            entdig = None

        A1 = "%s:%s:%s" % (user, realm, pw)
        A2 = "%s:%s" % (req.get_method(),
                        req.get_selector())
        if qop == 'auth':
            if nonce == self.last_nonce:
                self.nonce_count += 1
            else:
                self.nonce_count = 1
                self.last_nonce = nonce

            ncvalue = '%08x' % self.nonce_count
            cnonce = self.get_cnonce(nonce)
            noncebit = "%s:%s:%s:%s:%s" % (nonce, ncvalue, cnonce, qop, H(A2))
            respdig = KD(H(A1), noncebit)
        elif qop is None:
            respdig = KD(H(A1), "%s:%s" % (nonce, H(A2)))
        else:
            logger = logging.getLogger("mechanize.auth")
            logger.info("digest auth auth-int qop is not supported, not "
                        "handling digest authentication")
            return None


        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
               'response="%s"' % (user, realm, nonce, req.get_selector(),
                                  respdig)
        if opaque:
            base += ', opaque="%s"' % opaque
        if entdig:
            base += ', digest="%s"' % entdig
        base += ', algorithm="%s"' % algorithm
        if qop:
            base += ', qop=auth, nc=%s, cnonce="%s"' % (ncvalue, cnonce)
        return base

    def get_algorithm_impls(self, algorithm):
        algorithm = algorithm.upper()
        if algorithm == 'MD5':
            H = md5_digest
        elif algorithm == 'SHA':
            H = sha1_digest
        KD = lambda s, d: H("%s:%s" % (s, d))
        return H, KD

    def get_entity_digest(self, data, chal):
        return None

    def __copy__(self):
        return self.__class__(self.passwd.__copy__())


class HTTPDigestAuthHandler(BaseHandler, AbstractDigestAuthHandler):
    """An authentication protocol defined by RFC 2069

    Digest authentication improves on basic authentication because it
    does not transmit passwords in the clear.
    """

    auth_header = 'Authorization'
    handler_order = 490

    def http_error_401(self, req, fp, code, msg, headers):
        host = urlparse(req.get_full_url())[1]
        retry = self.http_error_auth_reqed('www-authenticate',
                                           host, req, headers)
        self.reset_retry_count()
        return retry

    def __copy__(self):
        return AbstractDigestAuthHandler.__copy__(self)


class ProxyDigestAuthHandler(BaseHandler, AbstractDigestAuthHandler):

    auth_header = 'Proxy-Authorization'
    handler_order = 490

    def http_error_407(self, req, fp, code, msg, headers):
        host = req.get_host()
        retry = self.http_error_auth_reqed('proxy-authenticate',
                                           host, req, headers)
        self.reset_retry_count()
        return retry

    def __copy__(self):
        return AbstractDigestAuthHandler.__copy__(self)


class AbstractHTTPHandler(BaseHandler):

    def __init__(self, debuglevel=0):
        self._debuglevel = debuglevel

    def set_http_debuglevel(self, level):
        self._debuglevel = level

    def do_request_(self, request):
        host = request.get_host()
        if not host:
            raise URLError('no host given')

        if request.has_data():
            data = request.get_data()
            if not request.has_header('Content-type'):
                request.add_unredirected_header(
                    'Content-type',
                    'application/x-www-form-urlencoded')
            if not request.has_header('Content-length'):
                request.add_unredirected_header(
                    'Content-length', '%d' % len(data))

        sel_host = host
        if request.has_proxy():
            scheme, sel = splittype(request.get_selector())
            sel_host, sel_path = splithost(sel)

        for name, value in self.parent.addheaders:
            name = name.capitalize()
            if not request.has_header(name):
                request.add_unredirected_header(name, value)
        if not request.has_header('Host'):
            request.add_unredirected_header('Host', sel_host)

        return request

    def do_open(self, http_class, req):
        """Return an addinfourl object for the request, using http_class.

        http_class must implement the HTTPConnection API from httplib.
        The addinfourl return value is a file-like object.  It also
        has methods and attributes including:
            - info(): return a HTTPMessage object for the headers
            - geturl(): return the original request URL
            - code: HTTP status code
        """
        host_port = req.get_host()
        if not host_port:
            raise URLError('no host given')

        h = http_class(host_port, timeout=req.timeout)
        h.set_debuglevel(self._debuglevel)

        headers = OrderedDict(req.headers)
        for key, val in iteritems(req.unredirected_hdrs):
            headers[key] = val
        headers["Connection"] = "close"
        if is_py2:
            headers = OrderedDict(
                    (str(name.title()), str(val))
                    for name, val in iteritems(headers))
        else:
            headers = OrderedDict(
                    (as_unicode(name, 'iso-8859-1').title(),
                     as_unicode(val, 'iso-8859-1'))
                    for name, val in iteritems(headers))

        if req._tunnel_host:
            set_tunnel = h.set_tunnel if hasattr(
                h, "set_tunnel") else h._set_tunnel
            tunnel_headers = {}
            proxy_auth_hdr = "Proxy-Authorization"
            if proxy_auth_hdr in headers:
                tunnel_headers[proxy_auth_hdr] = headers[proxy_auth_hdr]
                del headers[proxy_auth_hdr]
            set_tunnel(req._tunnel_host, headers=tunnel_headers)

        if self.parent.finalize_request_headers is not None:
            self.parent.finalize_request_headers(req, headers)

        try:
            h.request(str(req.get_method()), str(req.get_selector()), req.data,
                      headers)
            r = h.getresponse()
        except socket.error as err:
            raise URLError(err)

        fp = create_readline_wrapper(r)

        resp = closeable_response(
            fp, r.msg, req.get_full_url(), r.status, r.reason,
            getattr(r, 'version', None))
        return resp

    def __copy__(self):
        return self.__class__(self._debuglevel)


class HTTPHandler(AbstractHTTPHandler):

    def http_open(self, req):
        return self.do_open(HTTPConnection, req)

    http_request = AbstractHTTPHandler.do_request_


class HTTPSHandler(AbstractHTTPHandler):

    def __init__(self, client_cert_manager=None):
        AbstractHTTPHandler.__init__(self)
        self.client_cert_manager = client_cert_manager
        self.ssl_context = None

    def https_open(self, req):
        key_file = cert_file = None
        if self.client_cert_manager is not None:
            key_file, cert_file = self.client_cert_manager.find_key_cert(
                req.get_full_url())
        if self.ssl_context is None:
            conn_factory = partial(
                HTTPSConnection, key_file=key_file,
                cert_file=cert_file)
        else:
            conn_factory = partial(
                HTTPSConnection, key_file=key_file,
                cert_file=cert_file, context=self.ssl_context)
        return self.do_open(conn_factory, req)

    https_request = AbstractHTTPHandler.do_request_

    def __copy__(self):
        ans = self.__class__(self.client_cert_manager)
        ans._debuglevel = self._debuglevel
        ans.ssl_context = self.ssl_context
        return ans


class HTTPCookieProcessor(BaseHandler):
    """Handle HTTP cookies.

    Public attributes:

    cookiejar: CookieJar instance

    """

    def __init__(self, cookiejar=None):
        if cookiejar is None:
            cookiejar = CookieJar()
        self.cookiejar = cookiejar

    def http_request(self, request):
        self.cookiejar.add_cookie_header(request)
        return request

    def http_response(self, request, response):
        self.cookiejar.extract_cookies(response, request)
        return response

    def __copy__(self):
        return self.__class__(self.cookiejar)

    https_request = http_request
    https_response = http_response


class UnknownHandler(BaseHandler):

    def unknown_open(self, req):
        type = req.get_type()
        raise URLError('unknown url type: %s' % type)


def parse_keqv_list(ln):
    """Parse list of key=value strings where keys are not duplicated."""
    parsed = {}
    for elt in ln:
        k, v = elt.split('=', 1)
        if v[0:1] == '"' and v[-1:] == '"':
            v = v[1:-1]
        parsed[k] = v
    return parsed


def parse_http_list(s):
    """Parse lists as described by RFC 2068 Section 2.

    In particular, parse comma-separated lists where the elements of
    the list may include quoted-strings.  A quoted-string could
    contain a comma.  A non-quoted string could have quotes in the
    middle.  Neither commas nor quotes count if they are escaped.
    Only double-quotes count, not single-quotes.
    """
    res = []
    part = ''

    escape = quote = False
    for cur in s:
        if escape:
            part += cur
            escape = False
            continue
        if quote:
            if cur == '\\':
                escape = True
                continue
            elif cur == '"':
                quote = False
            part += cur
            continue

        if cur == ',':
            res.append(part)
            part = ''
            continue

        if cur == '"':
            quote = True

        part += cur

    if part:
        res.append(part)

    return list(filter(None, (part_.strip() for part_ in res)))


class FileHandler(BaseHandler):

    def file_open(self, req):
        url = req.get_selector()
        if url[:2] == '//' and url[2:3] != '/':
            req.type = 'ftp'
            return self.parent.open(req)
        else:
            return self.open_local_file(req)

    names = None

    def get_names(self):
        if FileHandler.names is None:
            try:
                FileHandler.names = (socket.gethostbyname('localhost'),
                                     socket.gethostbyname(socket.gethostname())
                                     )
            except socket.gaierror:
                FileHandler.names = (socket.gethostbyname('localhost'),)
        return FileHandler.names

    def open_local_file(self, req):
        import email.utils as emailutils
        import mimetypes
        host = req.get_host()
        file = req.get_selector()
        try:
            localfile = url2pathname(file)
        except IOError as err:
            raise URLError(err)
        try:
            stats = os.stat(localfile)
            size = stats.st_size
            modified = emailutils.formatdate(stats.st_mtime, usegmt=True)
            mtype = mimetypes.guess_type(file)[0]
            headers = create_response_info(BytesIO(
                ('Content-type: %s\nContent-length: %d\nLast-modified: %s\n' %
                    (mtype or 'text/plain', size, modified)).encode(
                        'iso-8859-1')))
            if host:
                host, port = splitport(host)
            if not host or (
                    not port and socket.gethostbyname(host) in self.get_names()
            ):
                fp = open(localfile, 'rb')
                return closeable_response(fp, headers, 'file:' + file)
        except OSError as msg:
            raise URLError(msg)
        raise URLError('file not on local host')


class FTPHandler(BaseHandler):

    def ftp_open(self, req):
        import ftplib
        import mimetypes
        host = req.get_host()
        if not host:
            raise URLError('ftp error: no host given')
        host, port = splitport(host)
        if port is None:
            port = ftplib.FTP_PORT
        else:
            port = int(port)

        user, host = splituser(host)
        if user:
            user, passwd = splitpasswd(user)
        else:
            passwd = None
        host = unquote(host)
        user = unquote(user or '')
        passwd = unquote(passwd or '')

        try:
            host = socket.gethostbyname(host)
        except socket.error as msg:
            raise URLError(msg)
        path, attrs = splitattr(req.get_selector())
        dirs = path.split('/')
        dirs = list(map(unquote, dirs))
        dirs, file = dirs[:-1], dirs[-1]
        if dirs and not dirs[0]:
            dirs = dirs[1:]
        try:
            fw = self.connect_ftp(user, passwd, host, port, dirs, req.timeout)
            type = file and 'I' or 'D'
            for attr in attrs:
                attr, value = splitvalue(attr)
                if attr.lower() == 'type' and \
                   value in ('a', 'A', 'i', 'I', 'd', 'D'):
                    type = value.upper()
            fp, retrlen = fw.retrfile(file, type)
            headers = ""
            mtype = mimetypes.guess_type(req.get_full_url())[0]
            if mtype:
                headers += "Content-type: %s\n" % mtype
            if retrlen is not None and retrlen >= 0:
                headers += "Content-length: %d\n" % retrlen
            sf = BytesIO(headers.encode('iso-8859-1'))
            headers = create_response_info(sf)
            return closeable_response(fp, headers, req.get_full_url())
        except ftplib.all_errors as msg:
            raise_with_traceback(URLError('ftp error: %s' % msg))

    def connect_ftp(self, user, passwd, host, port, dirs, timeout):
        try:
            fw = ftpwrapper(user, passwd, host, port, dirs, timeout)
        except TypeError:
            fw = ftpwrapper(user, passwd, host, port, dirs)
        return fw


class CacheFTPHandler(FTPHandler):

    def __init__(self):
        self.cache = {}
        self.timeout = {}
        self.soonest = 0
        self.delay = 60
        self.max_conns = 16

    def setTimeout(self, t):
        self.delay = t

    def setMaxConns(self, m):
        self.max_conns = m

    def connect_ftp(self, user, passwd, host, port, dirs, timeout):
        key = user, host, port, '/'.join(dirs), timeout
        if key in self.cache:
            self.timeout[key] = time.time() + self.delay
        else:
            self.cache[key] = ftpwrapper(
                user, passwd, host, port, dirs, timeout)
            self.timeout[key] = time.time() + self.delay
        self.check_cache()
        return self.cache[key]

    def check_cache(self):
        t = time.time()
        if self.soonest <= t:
            for k, v in iteritems(self.timeout):
                if v < t:
                    self.cache[k].close()
                    del self.cache[k]
                    del self.timeout[k]
        self.soonest = min(self.timeout.values())

        if len(self.cache) == self.max_conns:
            for k, v in iteritems(self.timeout):
                if v == self.soonest:
                    del self.cache[k]
                    del self.timeout[k]
                    break
            self.soonest = min(self.timeout.values())
