
import io
import logging
import select
import socket
import struct
import sys
import time

try:
    import http.client as httplib
    import urllib.parse as urlparse
except ImportError:
    import httplib
    import urlparse

import kdcproxy.codec as codec
from kdcproxy.config import MetaResolver


class HTTPException(Exception):

    def __init__(self, code, msg, headers=[]):
        headers = list(filter(lambda h: h[0] != 'Content-Length', headers))

        if 'Content-Type' not in dict(headers):
            headers.append(('Content-Type', 'text/plain; charset=utf-8'))

        if sys.version_info.major == 3 and isinstance(msg, str):
            msg = bytes(msg, "utf-8")

        headers.append(('Content-Length', str(len(msg))))

        super(HTTPException, self).__init__(code, msg, headers)
        self.code = code
        self.message = msg
        self.headers = headers

    def __str__(self):
        return "%d %s" % (self.code, httplib.responses[self.code])


class Application:
    MAX_LENGTH = 128 * 1024
    SOCKTYPES = {
        "tcp": socket.SOCK_STREAM,
        "udp": socket.SOCK_DGRAM,
    }

    def __init__(self):
        self.__resolver = MetaResolver()

    def __await_reply(self, pr, rsocks, wsocks, timeout):
        extra = 0
        read_buffers = {}
        while (timeout + extra) > time.time():
            if not wsocks and not rsocks:
                break

            r, w, x = select.select(rsocks, wsocks, rsocks + wsocks,
                                    (timeout + extra) - time.time())
            for sock in x:
                sock.close()
                try:
                    rsocks.remove(sock)
                except ValueError:
                    pass
                try:
                    wsocks.remove(sock)
                except ValueError:
                    pass

            for sock in w:
                try:
                    if self.sock_type(sock) == socket.SOCK_DGRAM:
                        sock.sendall(pr.request[4:])
                    else:
                        sock.sendall(pr.request)
                        extra = 10
                except Exception:
                    logging.exception('Error in recv() of %s', sock)
                    continue
                rsocks.append(sock)
                wsocks.remove(sock)

            for sock in r:
                try:
                    reply = self.__handle_recv(sock, read_buffers)
                except Exception:
                    logging.exception('Error in recv() of %s', sock)
                    if self.sock_type(sock) == socket.SOCK_STREAM:
                        rsocks.remove(sock)
                else:
                    if reply is not None:
                        return reply

        return None

    def __handle_recv(self, sock, read_buffers):
        if self.sock_type(sock) == socket.SOCK_DGRAM:
            reply = sock.recv(1048576)
            reply = struct.pack("!I", len(reply)) + reply
            return reply
        else:
            buf = read_buffers.get(sock)
            part = sock.recv(1048576)
            if buf is None:
                if len(part) > 4:
                    (length, ) = struct.unpack("!I", part[0:4])
                    if length + 4 == len(part):
                        return part
                read_buffers[sock] = buf = io.BytesIO()

            if part:
                buf.write(part)
                return None
            else:
                read_buffers.pop(sock)
                reply = buf.getvalue()
                return reply

    def __filter_addr(self, addr):
        if addr[0] not in (socket.AF_INET, socket.AF_INET6):
            return False

        if addr[1] not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            return False

        if addr[2] not in (socket.IPPROTO_TCP, socket.IPPROTO_UDP):
            return False

        return True

    def sock_type(self, sock):
        try:
            return sock.type & ~socket.SOCK_NONBLOCK
        except AttributeError:
            return sock.type

    def __call__(self, env, start_response):
        try:
            method = env["REQUEST_METHOD"].upper()
            if method != "POST":
                raise HTTPException(405, "Method not allowed (%s)." % method)

            try:
                length = int(env["CONTENT_LENGTH"])
            except AttributeError:
                raise HTTPException(411, "Length required.")
            if length < 0:
                raise HTTPException(411, "Length required.")
            if length > self.MAX_LENGTH:
                raise HTTPException(413, "Request entity too large.")
            try:
                pr = codec.decode(env["wsgi.input"].read(length))
            except codec.ParsingError as e:
                raise HTTPException(400, e.message)

            servers = self.__resolver.lookup(
                pr.realm,
                kpasswd=isinstance(pr, codec.KPASSWDProxyRequest)
            )
            if not servers:
                raise HTTPException(503, "Can't find remote (%s)." % pr)

            reply = None
            wsocks = []
            rsocks = []
            for server in map(urlparse.urlparse, servers):
                scheme = server.scheme.lower().split("+", 1)
                if scheme[0] not in ("kerberos", "kpasswd"):
                    continue
                if len(scheme) > 1 and scheme[1] not in ("tcp", "udp"):
                    continue

                try:
                    port = server.port
                    if port is None:
                        port = scheme[0]
                    addrs = socket.getaddrinfo(server.hostname, port)
                except socket.gaierror:
                    continue

                addrs = tuple(sorted(filter(self.__filter_addr, addrs)))
                for addr in addrs + (None,):
                    if addr is not None:
                        if (len(scheme) > 1
                                and addr[1] != self.SOCKTYPES[scheme[1]]):
                            continue

                        sock = socket.socket(*addr[:3])
                        sock.setblocking(0)

                        try:
                            sock.connect(addr[4])
                        except socket.error as e:
                            if e.errno != 115:
                                sock.close()
                                continue
                        except io.BlockingIOError:
                            pass
                        wsocks.append(sock)

                    for sock in tuple(rsocks):
                        if self.sock_type(sock) == socket.SOCK_DGRAM:
                            wsocks.append(sock)
                            rsocks.remove(sock)

                    timeout = time.time() + (15 if addr is None else 2)
                    reply = self.__await_reply(pr, rsocks, wsocks, timeout)
                    if reply is not None:
                        break

                if reply is not None:
                    break

            for sock in rsocks + wsocks:
                sock.close()

            if reply is None:
                raise HTTPException(503, "Remote unavailable (%s)." % pr)

            raise HTTPException(200, codec.encode(reply),
                                [("Content-Type", "application/kerberos")])
        except HTTPException as e:
            start_response(str(e), e.headers)
            return [e.message]

application = Application()
