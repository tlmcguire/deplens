
"""Helper class for TLSConnection."""
from __future__ import generators

from .utils.compat import *
from .utils.cryptomath import *
from .utils.cipherfactory import createAES, createRC4, createTripleDES
from .utils.codec import *
from .errors import *
from .messages import *
from .mathtls import *
from .constants import *
from .utils.cryptomath import getRandomBytes

import socket
import errno
import traceback

class _ConnectionState(object):
    def __init__(self):
        self.macContext = None
        self.encContext = None
        self.seqnum = 0

    def getSeqNumBytes(self):
        w = Writer()
        w.add(self.seqnum, 8)
        self.seqnum += 1
        return w.bytes


class TLSRecordLayer(object):
    """
    This class handles data transmission for a TLS connection.

    Its only subclass is L{tlslite.TLSConnection.TLSConnection}.  We've
    separated the code in this class from TLSConnection to make things
    more readable.


    @type sock: socket.socket
    @ivar sock: The underlying socket object.

    @type session: L{tlslite.Session.Session}
    @ivar session: The session corresponding to this connection.

    Due to TLS session resumption, multiple connections can correspond
    to the same underlying session.

    @type version: tuple
    @ivar version: The TLS version being used for this connection.

    (3,0) means SSL 3.0, and (3,1) means TLS 1.0.

    @type closed: bool
    @ivar closed: If this connection is closed.

    @type resumed: bool
    @ivar resumed: If this connection is based on a resumed session.

    @type allegedSrpUsername: str or None
    @ivar allegedSrpUsername:  This is set to the SRP username
    asserted by the client, whether the handshake succeeded or not.
    If the handshake fails, this can be inspected to determine
    if a guessing attack is in progress against a particular user
    account.

    @type closeSocket: bool
    @ivar closeSocket: If the socket should be closed when the
    connection is closed, defaults to True (writable).

    If you set this to True, TLS Lite will assume the responsibility of
    closing the socket when the TLS Connection is shutdown (either
    through an error or through the user calling close()).  The default
    is False.

    @type ignoreAbruptClose: bool
    @ivar ignoreAbruptClose: If an abrupt close of the socket should
    raise an error (writable).

    If you set this to True, TLS Lite will not raise a
    L{tlslite.errors.TLSAbruptCloseError} exception if the underlying
    socket is unexpectedly closed.  Such an unexpected closure could be
    caused by an attacker.  However, it also occurs with some incorrect
    TLS implementations.

    You should set this to True only if you're not worried about an
    attacker truncating the connection, and only if necessary to avoid
    spurious errors.  The default is False.

    @sort: __init__, read, readAsync, write, writeAsync, close, closeAsync,
    getCipherImplementation, getCipherName
    """

    def __init__(self, sock):
        self.sock = sock

        self.session = None

        self._client = None

        self._handshakeBuffer = []
        self.clearReadBuffer()
        self.clearWriteBuffer()

        self._handshake_md5 = hashlib.md5()
        self._handshake_sha = hashlib.sha1()
        self._handshake_sha256 = hashlib.sha256()

        self.version = (0,0)
        self._versionCheck = False

        self._writeState = _ConnectionState()
        self._readState = _ConnectionState()
        self._pendingWriteState = _ConnectionState()
        self._pendingReadState = _ConnectionState()

        self.closed = True
        self._refCount = 0

        self.resumed = False

        self.allegedSrpUsername = None

        self.closeSocket = True

        self.ignoreAbruptClose = False

        self.fault = None

    def clearReadBuffer(self):
        self._readBuffer = b''

    def clearWriteBuffer(self):
        self._send_writer = None



    def read(self, max=None, min=1):
        """Read some data from the TLS connection.

        This function will block until at least 'min' bytes are
        available (or the connection is closed).

        If an exception is raised, the connection will have been
        automatically closed.

        @type max: int
        @param max: The maximum number of bytes to return.

        @type min: int
        @param min: The minimum number of bytes to return

        @rtype: str
        @return: A string of no more than 'max' bytes, and no fewer
        than 'min' (unless the connection has been closed, in which
        case fewer than 'min' bytes may be returned).

        @raise socket.error: If a socket error occurs.
        @raise tlslite.errors.TLSAbruptCloseError: If the socket is closed
        without a preceding alert.
        @raise tlslite.errors.TLSAlert: If a TLS alert is signalled.
        """
        for result in self.readAsync(max, min):
            pass
        return result

    def readAsync(self, max=None, min=1):
        """Start a read operation on the TLS connection.

        This function returns a generator which behaves similarly to
        read().  Successive invocations of the generator will return 0
        if it is waiting to read from the socket, 1 if it is waiting
        to write to the socket, or a string if the read operation has
        completed.

        @rtype: iterable
        @return: A generator; see above for details.
        """
        try:
            while len(self._readBuffer)<min and not self.closed:
                try:
                    for result in self._getMsg(ContentType.application_data):
                        if result in (0,1):
                            yield result
                    applicationData = result
                    self._readBuffer += applicationData.write()
                except TLSRemoteAlert as alert:
                    if alert.description != AlertDescription.close_notify:
                        raise
                except TLSAbruptCloseError:
                    if not self.ignoreAbruptClose:
                        raise
                    else:
                        self._shutdown(True)

            if max == None:
                max = len(self._readBuffer)

            returnBytes = self._readBuffer[:max]
            self._readBuffer = self._readBuffer[max:]
            yield bytes(returnBytes)
        except GeneratorExit:
            raise
        except:
            self._shutdown(False)
            raise

    def unread(self, b):
        """Add bytes to the front of the socket read buffer for future
        reading. Be careful using this in the context of select(...): if you
        unread the last data from a socket, that won't wake up selected waiters,
        and those waiters may hang forever.
        """
        self._readBuffer = b + self._readBuffer

    def write(self, s):
        """Write some data to the TLS connection.

        This function will block until all the data has been sent.

        If an exception is raised, the connection will have been
        automatically closed.

        @type s: str
        @param s: The data to transmit to the other party.

        @raise socket.error: If a socket error occurs.
        """
        for result in self.writeAsync(s):
            pass

    def writeAsync(self, s):
        """Start a write operation on the TLS connection.

        This function returns a generator which behaves similarly to
        write().  Successive invocations of the generator will return
        1 if it is waiting to write to the socket, or will raise
        StopIteration if the write operation has completed.

        @rtype: iterable
        @return: A generator; see above for details.
        """
        try:
            if self.closed:
                raise TLSClosedConnectionError("attempt to write to closed connection")

            index = 0
            blockSize = 16384
            randomizeFirstBlock = True
            while 1:
                startIndex = index * blockSize
                endIndex = startIndex + blockSize
                if startIndex >= len(s):
                    break
                if endIndex > len(s):
                    endIndex = len(s)
                block = bytearray(s[startIndex : endIndex])
                applicationData = ApplicationData().create(block)
                for result in self._sendMsg(applicationData, \
                                            randomizeFirstBlock):
                    yield result
                randomizeFirstBlock = False
                index += 1
        except GeneratorExit:
            raise
        except Exception:
            self._shutdown(self.ignoreAbruptClose)
            raise

    def close(self):
        """Close the TLS connection.

        This function will block until it has exchanged close_notify
        alerts with the other party.  After doing so, it will shut down the
        TLS connection.  Further attempts to read through this connection
        will return "".  Further attempts to write through this connection
        will raise ValueError.

        If makefile() has been called on this connection, the connection
        will be not be closed until the connection object and all file
        objects have been closed.

        Even if an exception is raised, the connection will have been
        closed.

        @raise socket.error: If a socket error occurs.
        @raise tlslite.errors.TLSAbruptCloseError: If the socket is closed
        without a preceding alert.
        @raise tlslite.errors.TLSAlert: If a TLS alert is signalled.
        """
        if not self.closed:
            for result in self._decrefAsync():
                pass

    _decref_socketios = close

    def closeAsync(self):
        """Start a close operation on the TLS connection.

        This function returns a generator which behaves similarly to
        close().  Successive invocations of the generator will return 0
        if it is waiting to read from the socket, 1 if it is waiting
        to write to the socket, or will raise StopIteration if the
        close operation has completed.

        @rtype: iterable
        @return: A generator; see above for details.
        """
        if not self.closed:
            for result in self._decrefAsync():
                yield result

    def _decrefAsync(self):
        self._refCount -= 1
        if self._refCount == 0 and not self.closed:
            try:
                for result in self._sendMsg(Alert().create(\
                        AlertDescription.close_notify, AlertLevel.warning)):
                    yield result
                alert = None
                if self.closeSocket:
                    self._shutdown(True)
                else:
                    while not alert:
                        for result in self._getMsg((ContentType.alert, \
                                                  ContentType.application_data)):
                            if result in (0,1):
                                yield result
                        if result.contentType == ContentType.alert:
                            alert = result
                    if alert.description == AlertDescription.close_notify:
                        self._shutdown(True)
                    else:
                        raise TLSRemoteAlert(alert)
            except (socket.error, TLSAbruptCloseError):
                self._shutdown(True)
            except GeneratorExit:
                raise
            except:
                self._shutdown(False)
                raise

    def getVersionName(self):
        """Get the name of this TLS version.

        @rtype: str
        @return: The name of the TLS version used with this connection.
        Either None, 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', or 'TLS 1.2'.
        """
        if self.version == (3,0):
            return "SSL 3.0"
        elif self.version == (3,1):
            return "TLS 1.0"
        elif self.version == (3,2):
            return "TLS 1.1"
        elif self.version == (3,3):
            return "TLS 1.2"
        else:
            return None

    def getCipherName(self):
        """Get the name of the cipher used with this connection.

        @rtype: str
        @return: The name of the cipher used with this connection.
        Either 'aes128', 'aes256', 'rc4', or '3des'.
        """
        if not self._writeState.encContext:
            return None
        return self._writeState.encContext.name

    def getCipherImplementation(self):
        """Get the name of the cipher implementation used with
        this connection.

        @rtype: str
        @return: The name of the cipher implementation used with
        this connection.  Either 'python', 'openssl', or 'pycrypto'.
        """
        if not self._writeState.encContext:
            return None
        return self._writeState.encContext.implementation



    def send(self, s):
        """Send data to the TLS connection (socket emulation).

        @raise socket.error: If a socket error occurs.
        """
        self.write(s)
        return len(s)

    def sendall(self, s):
        """Send data to the TLS connection (socket emulation).

        @raise socket.error: If a socket error occurs.
        """
        self.write(s)

    def recv(self, bufsize):
        """Get some data from the TLS connection (socket emulation).

        @raise socket.error: If a socket error occurs.
        @raise tlslite.errors.TLSAbruptCloseError: If the socket is closed
        without a preceding alert.
        @raise tlslite.errors.TLSAlert: If a TLS alert is signalled.
        """
        return self.read(bufsize)

    def recv_into(self, b):
        data = self.read(len(b))
        if not data:
            return None
        b[:len(data)] = data
        return len(data)

    def makefile(self, mode='r', bufsize=-1):
        """Create a file object for the TLS connection (socket emulation).

        @rtype: L{socket._fileobject}
        """
        self._refCount += 1
        if sys.version_info < (3,):
            return socket._fileobject(self, mode, bufsize, close=True)
        else:
            return socket.SocketIO(self, mode)

    def getsockname(self):
        """Return the socket's own address (socket emulation)."""
        return self.sock.getsockname()

    def getpeername(self):
        """Return the remote address to which the socket is connected
        (socket emulation)."""
        return self.sock.getpeername()

    def settimeout(self, value):
        """Set a timeout on blocking socket operations (socket emulation)."""
        return self.sock.settimeout(value)

    def gettimeout(self):
        """Return the timeout associated with socket operations (socket
        emulation)."""
        return self.sock.gettimeout()

    def setsockopt(self, level, optname, value):
        """Set the value of the given socket option (socket emulation)."""
        return self.sock.setsockopt(level, optname, value)

    def shutdown(self, how):
        """Shutdown the underlying socket."""
        return self.sock.shutdown(how)

    def fileno(self):
        """Not implement in TLS Lite."""
        raise NotImplementedError()



    def _shutdown(self, resumable):
        self._writeState = _ConnectionState()
        self._readState = _ConnectionState()
        self.version = (0,0)
        self._versionCheck = False
        self.closed = True
        if self.closeSocket:
            self.sock.close()

        if not resumable and self.session:
            self.session.resumable = False


    def _sendError(self, alertDescription, errorStr=None):
        alert = Alert().create(alertDescription, AlertLevel.fatal)
        for result in self._sendMsg(alert):
            yield result
        self._shutdown(False)
        raise TLSLocalAlert(alert, errorStr)

    def _sendMsgs(self, msgs):
        randomizeFirstBlock = True
        for msg in msgs:
            for result in self._sendMsg(msg, randomizeFirstBlock):
                yield result
            randomizeFirstBlock = True

    def _sendMsg(self, msg, randomizeFirstBlock = True):
        if not self.closed and randomizeFirstBlock and self.version <= (3,1) \
                and self._writeState.encContext \
                and self._writeState.encContext.isBlockCipher \
                and isinstance(msg, ApplicationData):
            msgFirstByte = msg.splitFirstByte()
            for result in self._sendMsg(msgFirstByte,
                                       randomizeFirstBlock = False):
                yield result

        b = msg.write()

        if len(b) == 0:
            return

        contentType = msg.contentType

        if contentType == ContentType.handshake:
            self._handshake_md5.update(compat26Str(b))
            self._handshake_sha.update(compat26Str(b))
            self._handshake_sha256.update(compat26Str(b))

        if self._writeState.macContext:
            seqnumBytes = self._writeState.getSeqNumBytes()
            mac = self._writeState.macContext.copy()
            mac.update(compatHMAC(seqnumBytes))
            mac.update(compatHMAC(bytearray([contentType])))
            if self.version == (3,0):
                mac.update( compatHMAC( bytearray([len(b)//256] )))
                mac.update( compatHMAC( bytearray([len(b)%256] )))
            elif self.version in ((3,1), (3,2), (3,3)):
                mac.update(compatHMAC( bytearray([self.version[0]] )))
                mac.update(compatHMAC( bytearray([self.version[1]] )))
                mac.update( compatHMAC( bytearray([len(b)//256] )))
                mac.update( compatHMAC( bytearray([len(b)%256] )))
            else:
                raise AssertionError()
            mac.update(compatHMAC(b))
            macBytes = bytearray(mac.digest())
            if self.fault == Fault.badMAC:
                macBytes[0] = (macBytes[0]+1) % 256

        if self._writeState.encContext:
            if self._writeState.encContext.isBlockCipher:

                if self.version >= (3,2):
                    b = self.fixedIVBlock + b

                currentLength = len(b) + len(macBytes)
                blockLength = self._writeState.encContext.block_size
                paddingLength = blockLength - 1 - (currentLength % blockLength)

                paddingBytes = bytearray([paddingLength] * (paddingLength+1))
                if self.fault == Fault.badPadding:
                    paddingBytes[0] = (paddingBytes[0]+1) % 256
                endBytes = macBytes + paddingBytes
                b += endBytes
                b = self._writeState.encContext.encrypt(b)

            else:
                b += macBytes
                b = self._writeState.encContext.encrypt(b)

        r = RecordHeader3().create(self.version, contentType, len(b))
        s = r.write() + b
        while 1:
            try:
                bytesSent = self.sock.send(s)
            except socket.error as why:
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 1
                    continue
                else:
                    if contentType == ContentType.handshake:

                        for result in self._getNextRecord():
                            if result in (0,1):
                                yield result

                        self._shutdown(False)

                        recordHeader, p = result
                        if recordHeader.type == ContentType.alert:
                            alert = Alert().parse(p)
                            raise TLSRemoteAlert(alert)
                    else:
                        raise
            if bytesSent == len(s):
                return
            s = s[bytesSent:]
            yield 1


    def _getMsg(self, expectedType, secondaryType=None, constructorType=None):
        try:
            if not isinstance(expectedType, tuple):
                expectedType = (expectedType,)

            while 1:
                for result in self._getNextRecord():
                    if result in (0,1):
                        yield result
                recordHeader, p = result

                if recordHeader.type == ContentType.application_data:
                    if p.index == len(p.bytes):
                        continue

                if recordHeader.type not in expectedType:

                    if recordHeader.type == ContentType.alert:
                        alert = Alert().parse(p)

                        if alert.level == AlertLevel.warning or \
                           alert.description == AlertDescription.close_notify:

                            try:
                                alertMsg = Alert()
                                alertMsg.create(AlertDescription.close_notify,
                                                AlertLevel.warning)
                                for result in self._sendMsg(alertMsg):
                                    yield result
                            except socket.error:
                                pass

                            if alert.description == \
                                   AlertDescription.close_notify:
                                self._shutdown(True)
                            elif alert.level == AlertLevel.warning:
                                self._shutdown(False)

                        else:
                            self._shutdown(False)

                        raise TLSRemoteAlert(alert)

                    if recordHeader.type == ContentType.handshake:
                        subType = p.get(1)
                        reneg = False
                        if self._client:
                            if subType == HandshakeType.hello_request:
                                reneg = True
                        else:
                            if subType == HandshakeType.client_hello:
                                reneg = True
                        if reneg:
                            alertMsg = Alert()
                            alertMsg.create(AlertDescription.no_renegotiation,
                                            AlertLevel.warning)
                            for result in self._sendMsg(alertMsg):
                                yield result
                            continue

                    for result in self._sendError(\
                            AlertDescription.unexpected_message,
                            "received type=%d" % recordHeader.type):
                        yield result

                break

            if recordHeader.type == ContentType.change_cipher_spec:
                yield ChangeCipherSpec().parse(p)
            elif recordHeader.type == ContentType.alert:
                yield Alert().parse(p)
            elif recordHeader.type == ContentType.application_data:
                yield ApplicationData().parse(p)
            elif recordHeader.type == ContentType.handshake:
                if not isinstance(secondaryType, tuple):
                    secondaryType = (secondaryType,)

                if recordHeader.ssl2:
                    subType = p.get(1)
                    if subType != HandshakeType.client_hello:
                        for result in self._sendError(\
                                AlertDescription.unexpected_message,
                                "Can only handle SSLv2 ClientHello messages"):
                            yield result
                    if HandshakeType.client_hello not in secondaryType:
                        for result in self._sendError(\
                                AlertDescription.unexpected_message):
                            yield result
                    subType = HandshakeType.client_hello
                else:
                    subType = p.get(1)
                    if subType not in secondaryType:
                        for result in self._sendError(\
                                AlertDescription.unexpected_message,
                                "Expecting %s, got %s" % (str(secondaryType), subType)):
                            yield result

                self._handshake_md5.update(compat26Str(p.bytes))
                self._handshake_sha.update(compat26Str(p.bytes))
                self._handshake_sha256.update(compat26Str(p.bytes))

                if subType == HandshakeType.client_hello:
                    yield ClientHello(recordHeader.ssl2).parse(p)
                elif subType == HandshakeType.server_hello:
                    yield ServerHello().parse(p)
                elif subType == HandshakeType.certificate:
                    yield Certificate(constructorType).parse(p)
                elif subType == HandshakeType.certificate_request:
                    yield CertificateRequest(self.version).parse(p)
                elif subType == HandshakeType.certificate_verify:
                    yield CertificateVerify(self.version).parse(p)
                elif subType == HandshakeType.server_key_exchange:
                    yield ServerKeyExchange(constructorType).parse(p)
                elif subType == HandshakeType.server_hello_done:
                    yield ServerHelloDone().parse(p)
                elif subType == HandshakeType.client_key_exchange:
                    yield ClientKeyExchange(constructorType, \
                                            self.version).parse(p)
                elif subType == HandshakeType.finished:
                    yield Finished(self.version).parse(p)
                elif subType == HandshakeType.next_protocol:
                    yield NextProtocol().parse(p)
                else:
                    raise AssertionError()

        except SyntaxError as e:
            for result in self._sendError(AlertDescription.decode_error,
                                         formatExceptionTrace(e)):
                yield result


    def _getNextRecord(self):

        if self._handshakeBuffer:
            recordHeader, b = self._handshakeBuffer[0]
            self._handshakeBuffer = self._handshakeBuffer[1:]
            yield (recordHeader, Parser(b))
            return

        b = bytearray(0)
        recordHeaderLength = 1
        ssl2 = False
        while 1:
            try:
                s = self.sock.recv(recordHeaderLength-len(b))
            except socket.error as why:
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 0
                    continue
                else:
                    raise

            if len(s)==0:
                raise TLSAbruptCloseError()

            b += bytearray(s)
            if len(b)==1:
                if b[0] in ContentType.all:
                    ssl2 = False
                    recordHeaderLength = 5
                elif b[0] == 128:
                    ssl2 = True
                    recordHeaderLength = 2
                else:
                    raise SyntaxError()
            if len(b) == recordHeaderLength:
                break

        if ssl2:
            r = RecordHeader2().parse(Parser(b))
        else:
            r = RecordHeader3().parse(Parser(b))

        if r.length > 18432:
            for result in self._sendError(AlertDescription.record_overflow):
                yield result

        b = bytearray(0)
        while 1:
            try:
                s = self.sock.recv(r.length - len(b))
            except socket.error as why:
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 0
                    continue
                else:
                    raise

            if len(s)==0:
                    raise TLSAbruptCloseError()

            b += bytearray(s)
            if len(b) == r.length:
                break


        for result in self._decryptRecord(r.type, b):
            if result in (0,1): yield result
            else: break
        b = result
        p = Parser(b)

        if r.type != ContentType.handshake:
            yield (r, p)
        elif r.ssl2:
            yield (r, p)
        else:
            while 1:
                if p.index == len(b):
                    if not self._handshakeBuffer:
                        for result in self._sendError(\
                                AlertDescription.decode_error, \
                                "Received empty handshake record"):
                            yield result
                    break
                if p.index+4 > len(b):
                    for result in self._sendError(\
                            AlertDescription.decode_error,
                            "A record has a partial handshake message (1)"):
                        yield result
                p.get(1)
                msgLength = p.get(3)
                if p.index+msgLength > len(b):
                    for result in self._sendError(\
                            AlertDescription.decode_error,
                            "A record has a partial handshake message (2)"):
                        yield result

                handshakePair = (r, b[p.index-4 : p.index+msgLength])
                self._handshakeBuffer.append(handshakePair)
                p.index += msgLength

            recordHeader, b = self._handshakeBuffer[0]
            self._handshakeBuffer = self._handshakeBuffer[1:]
            yield (recordHeader, Parser(b))


    def _decryptRecord(self, recordType, b):
        if self._readState.encContext:

            if self._readState.encContext.isBlockCipher:
                blockLength = self._readState.encContext.block_size
                if len(b) % blockLength != 0:
                    for result in self._sendError(\
                            AlertDescription.decryption_failed,
                            "Encrypted data not a multiple of blocksize"):
                        yield result
                b = self._readState.encContext.decrypt(b)
                if self.version >= (3,2):
                    b = b[self._readState.encContext.block_size : ]

                if len(b) == 0:
                    for result in self._sendError(\
                            AlertDescription.decryption_failed,
                            "No data left after decryption and IV removal"):
                        yield result

                paddingGood = True
                paddingLength = b[-1]
                if (paddingLength+1) > len(b):
                    paddingGood=False
                    totalPaddingLength = 0
                else:
                    if self.version == (3,0):
                        totalPaddingLength = paddingLength+1
                    elif self.version in ((3,1), (3,2), (3,3)):
                        totalPaddingLength = paddingLength+1
                        paddingBytes = b[-totalPaddingLength:-1]
                        for byte in paddingBytes:
                            if byte != paddingLength:
                                paddingGood = False
                                totalPaddingLength = 0
                    else:
                        raise AssertionError()

            else:
                paddingGood = True
                b = self._readState.encContext.decrypt(b)
                totalPaddingLength = 0

            macGood = True
            macLength = self._readState.macContext.digest_size
            endLength = macLength + totalPaddingLength
            if endLength > len(b):
                macGood = False
            else:
                startIndex = len(b) - endLength
                endIndex = startIndex + macLength
                checkBytes = b[startIndex : endIndex]

                seqnumBytes = self._readState.getSeqNumBytes()
                b = b[:-endLength]
                mac = self._readState.macContext.copy()
                mac.update(compatHMAC(seqnumBytes))
                mac.update(compatHMAC(bytearray([recordType])))
                if self.version == (3,0):
                    mac.update( compatHMAC(bytearray( [len(b)//256] ) ))
                    mac.update( compatHMAC(bytearray( [len(b)%256] ) ))
                elif self.version in ((3,1), (3,2), (3,3)):
                    mac.update(compatHMAC(bytearray( [self.version[0]] ) ))
                    mac.update(compatHMAC(bytearray( [self.version[1]] ) ))
                    mac.update(compatHMAC(bytearray( [len(b)//256] ) ))
                    mac.update(compatHMAC(bytearray( [len(b)%256] ) ))
                else:
                    raise AssertionError()
                mac.update(compatHMAC(b))
                macBytes = bytearray(mac.digest())

                if macBytes != checkBytes:
                    macGood = False

            if not (paddingGood and macGood):
                for result in self._sendError(AlertDescription.bad_record_mac,
                                          "MAC failure (or padding failure)"):
                    yield result

        yield b

    def _handshakeStart(self, client):
        if not self.closed:
            raise ValueError("Renegotiation disallowed for security reasons")
        self._client = client
        self._handshake_md5 = hashlib.md5()
        self._handshake_sha = hashlib.sha1()
        self._handshake_sha256 = hashlib.sha256()
        self._handshakeBuffer = []
        self.allegedSrpUsername = None
        self._refCount = 1

    def _handshakeDone(self, resumed):
        self.resumed = resumed
        self.closed = False

    def _calcPendingStates(self, cipherSuite, masterSecret,
            clientRandom, serverRandom, implementations):
        if cipherSuite in CipherSuite.aes128Suites:
            keyLength = 16
            ivLength = 16
            createCipherFunc = createAES
        elif cipherSuite in CipherSuite.aes256Suites:
            keyLength = 32
            ivLength = 16
            createCipherFunc = createAES
        elif cipherSuite in CipherSuite.rc4Suites:
            keyLength = 16
            ivLength = 0
            createCipherFunc = createRC4
        elif cipherSuite in CipherSuite.tripleDESSuites:
            keyLength = 24
            ivLength = 8
            createCipherFunc = createTripleDES
        else:
            raise AssertionError()

        if cipherSuite in CipherSuite.shaSuites:
            macLength = 20
            digestmod = hashlib.sha1
        elif cipherSuite in CipherSuite.sha256Suites:
            macLength = 32
            digestmod = hashlib.sha256
        elif cipherSuite in CipherSuite.md5Suites:
            macLength = 16
            digestmod = hashlib.md5

        if self.version == (3,0):
            createMACFunc = createMAC_SSL
        elif self.version in ((3,1), (3,2), (3,3)):
            createMACFunc = createHMAC

        outputLength = (macLength*2) + (keyLength*2) + (ivLength*2)

        if self.version == (3,0):
            keyBlock = PRF_SSL(masterSecret,
                               serverRandom + clientRandom,
                               outputLength)
        elif self.version in ((3,1), (3,2)):
            keyBlock = PRF(masterSecret,
                           b"key expansion",
                           serverRandom + clientRandom,
                           outputLength)
        elif self.version == (3,3):
            keyBlock = PRF_1_2(masterSecret,
                           b"key expansion",
                           serverRandom + clientRandom,
                           outputLength)
        else:
            raise AssertionError()

        clientPendingState = _ConnectionState()
        serverPendingState = _ConnectionState()
        p = Parser(keyBlock)
        clientMACBlock = p.getFixBytes(macLength)
        serverMACBlock = p.getFixBytes(macLength)
        clientKeyBlock = p.getFixBytes(keyLength)
        serverKeyBlock = p.getFixBytes(keyLength)
        clientIVBlock  = p.getFixBytes(ivLength)
        serverIVBlock  = p.getFixBytes(ivLength)
        clientPendingState.macContext = createMACFunc(
            compatHMAC(clientMACBlock), digestmod=digestmod)
        serverPendingState.macContext = createMACFunc(
            compatHMAC(serverMACBlock), digestmod=digestmod)
        clientPendingState.encContext = createCipherFunc(clientKeyBlock,
                                                         clientIVBlock,
                                                         implementations)
        serverPendingState.encContext = createCipherFunc(serverKeyBlock,
                                                         serverIVBlock,
                                                         implementations)

        if self._client:
            self._pendingWriteState = clientPendingState
            self._pendingReadState = serverPendingState
        else:
            self._pendingWriteState = serverPendingState
            self._pendingReadState = clientPendingState

        if self.version >= (3,2) and ivLength:
            self.fixedIVBlock = getRandomBytes(ivLength)

    def _changeWriteState(self):
        self._writeState = self._pendingWriteState
        self._pendingWriteState = _ConnectionState()

    def _changeReadState(self):
        self._readState = self._pendingReadState
        self._pendingReadState = _ConnectionState()

    def _calcSSLHandshakeHash(self, masterSecret, label):
        imac_md5 = self._handshake_md5.copy()
        imac_sha = self._handshake_sha.copy()

        imac_md5.update(compatHMAC(label + masterSecret + bytearray([0x36]*48)))
        imac_sha.update(compatHMAC(label + masterSecret + bytearray([0x36]*40)))

        md5Bytes = MD5(masterSecret + bytearray([0x5c]*48) + \
                         bytearray(imac_md5.digest()))
        shaBytes = SHA1(masterSecret + bytearray([0x5c]*40) + \
                         bytearray(imac_sha.digest()))

        return md5Bytes + shaBytes

