```python
from __future__ import annotations

import io
import socket
import time
import typing
import warnings
from test import LONG_TIMEOUT, SHORT_TIMEOUT
from threading import Event
from unittest import mock
from urllib.parse import urlencode

import pytest

from dummyserver.server import HAS_IPV6_AND_DNS, NoIPv6Warning
from dummyserver.testcase import HTTPDummyServerTestCase, SocketDummyServerTestCase
from urllib3 import HTTPConnectionPool, encode_multipart_formdata
from urllib3._collections import HTTPHeaderDict
from urllib3.connection import _get_default_user_agent
from urllib3.exceptions import (
    ConnectTimeoutError,
    DecodeError,
    EmptyPoolError,
    MaxRetryError,
    NameResolutionError,
    NewConnectionError,
    ReadTimeoutError,
    UnrewindableBodyError,
)
from urllib3.fields import _TYPE_FIELD_VALUE_TUPLE
from urllib3.util import SKIP_HEADER, SKIPPABLE_HEADERS
from urllib3.util.retry import RequestHistory, Retry
from urllib3.util.timeout import _TYPE_TIMEOUT, Timeout

from .. import INVALID_SOURCE_ADDRESSES, TARPIT_HOST, VALID_SOURCE_ADDRESSES
from ..port_helpers import find_unused_port


def wait_for_socket(ready_event: Event) -> None:
    ready_event.wait()
    ready_event.clear()


class TestConnectionPoolTimeouts(SocketDummyServerTestCase):
    def test_timeout_float(self) -> None:
        block_event = Event()
        ready_event = self.start_basic_handler(block_send=block_event, num=2)

        with HTTPConnectionPool(self.host, self.port, retries=False) as pool:
            wait_for_socket(ready_event)
            with pytest.raises(ReadTimeoutError):
                pool.request("GET", "/", timeout=SHORT_TIMEOUT)
            block_event.set()

            wait_for_socket(ready_event)
            block_event.set()
            pool.request("GET", "/", timeout=LONG_TIMEOUT)

    def test_conn_closed(self) -> None:
        block_event = Event()
        self.start_basic_handler(block_send=block_event, num=1)

        with HTTPConnectionPool(
            self.host, self.port, timeout=SHORT_TIMEOUT, retries=False
        ) as pool:
            conn = pool._get_conn()
            pool._put_conn(conn)
            try:
                with pytest.raises(ReadTimeoutError):
                    pool.urlopen("GET", "/")
                if not conn.is_closed:
                    with pytest.raises(socket.error):
                        conn.sock.recv(1024)
            finally:
                pool._put_conn(conn)

            block_event.set()

    def test_timeout(self) -> None:
        block_event = Event()
        ready_event = self.start_basic_handler(block_send=block_event, num=3)

        short_timeout = Timeout(read=SHORT_TIMEOUT)
        with HTTPConnectionPool(
            self.host, self.port, timeout=short_timeout, retries=False
        ) as pool:
            wait_for_socket(ready_event)
            block_event.clear()
            with pytest.raises(ReadTimeoutError):
                pool.request("GET", "/")
            block_event.set()

        with HTTPConnectionPool(
            self.host, self.port, timeout=short_timeout, retries=False
        ) as pool:
            wait_for_socket(ready_event)
            now = time.time()
            with pytest.raises(ReadTimeoutError):
                pool.request("GET", "/", timeout=LONG_TIMEOUT)
            delta = time.time() - now

            message = "timeout was pool-level SHORT_TIMEOUT rather than request-level LONG_TIMEOUT"
            assert delta >= LONG_TIMEOUT, message
            block_event.set()

            wait_for_socket(ready_event)
            with pytest.raises(ReadTimeoutError):
                pool.request("GET", "/", timeout=SHORT_TIMEOUT)
            block_event.set()

    def test_connect_timeout(self) -> None:
        url = "/"
        host, port = TARPIT_HOST, 80
        timeout = Timeout(connect=SHORT_TIMEOUT)

        with HTTPConnectionPool(host, port, timeout=timeout) as pool:
            conn = pool._get_conn()
            with pytest.raises(ConnectTimeoutError):
                pool._make_request(conn, "GET", url)

            retries = Retry(connect=0)
            with pytest.raises(MaxRetryError):
                pool.request("GET", url, retries=retries)

        big_timeout = Timeout(read=LONG_TIMEOUT, connect=LONG_TIMEOUT)
        with HTTPConnectionPool(host, port, timeout=big_timeout, retries=False) as pool:
            conn = pool._get_conn()
            with pytest.raises(ConnectTimeoutError):
                pool._make_request(conn, "GET", url, timeout=timeout)

            pool._put_conn(conn)
            with pytest.raises(ConnectTimeoutError):
                pool.request("GET", url, timeout=timeout)

    def test_total_applies_connect(self) -> None:
        host, port = TARPIT_HOST, 80

        timeout = Timeout(total=None, connect=SHORT_TIMEOUT)
        with HTTPConnectionPool(host, port, timeout=timeout) as pool:
            conn = pool._get_conn()
            try:
                with pytest.raises(ConnectTimeoutError):
                    pool._make_request(conn, "GET", "/")
            finally:
                conn.close()

        timeout = Timeout(connect=3, read=5, total=SHORT_TIMEOUT)
        with HTTPConnectionPool(host, port, timeout=timeout) as pool:
            conn = pool._get_conn()
            try:
                with pytest.raises(ConnectTimeoutError):
                    pool._make_request(conn, "GET", "/")
            finally:
                conn.close()

    def test_total_timeout(self) -> None:
        block_event = Event()
        ready_event = self.start_basic_handler(block_send=block_event, num=2)

        wait_for_socket(ready_event)
        timeout = Timeout(connect=3, read=SHORT_TIMEOUT)
        with HTTPConnectionPool(
            self.host, self.port, timeout=timeout, retries=False
        ) as pool:
            with pytest.raises(ReadTimeoutError):
                pool.request("GET", "/")

            block_event.set()
            wait_for_socket(ready_event)
            block_event.clear()

        timeout = Timeout(connect=3, read=5, total=SHORT_TIMEOUT)
        with HTTPConnectionPool(
            self.host, self.port, timeout=timeout, retries=False
        ) as pool:
            with pytest.raises(ReadTimeoutError):
                pool.request("GET", "/")

    def test_create_connection_timeout(self) -> None:
        self.start_basic_handler(block_send=Event(), num=0)

        timeout = Timeout(connect=SHORT_TIMEOUT, total=LONG_TIMEOUT)
        with HTTPConnectionPool(
            TARPIT_HOST, self.port, timeout=timeout, retries=False
        ) as pool:
            conn = pool._new_conn()
            with pytest.raises(ConnectTimeoutError):
                conn.connect()


class TestConnectionPool(HTTPDummyServerTestCase):
    def test_get(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request("GET", "/specific_method", fields={"method": "GET"})
            assert r.status == 200, r.data

    def test_post_url(self) -> None:
        with HTTPConnectionPool(self.host, self.port) as pool:
            r = pool.request("POST", "/specific_method", fields={"method": "POST"})
            assert r.status == 20