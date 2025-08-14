import asyncio
import pytest
import asyncio
import struct

from asyncua import Client, Server, ua
from asyncua.ua.uaerrors import BadMaxConnectionsReached
from .conftest import port_num, find_free_port

pytestmark = pytest.mark.asyncio


async def test_max_connections_1(opc):
    opc.server.iserver.isession.__class__.max_connections = 1
    port = opc.server.endpoint.port
    if port == port_num:
        with pytest.raises(BadMaxConnectionsReached):
            async with Client(f'opc.tcp://127.0.0.1:{port}'):
                pass
    else:
        async with Client(f'opc.tcp://127.0.0.1:{port}'):
            with pytest.raises(BadMaxConnectionsReached):
                async with Client(f'opc.tcp://127.0.0.1:{port}'):
                    pass
    opc.server.iserver.isession.__class__.max_connections = 1000


async def test_dos_server(opc):
    port = opc.server.endpoint.port
    async with Client(f'opc.tcp://127.0.0.1:{port}') as c:
        message_type, chunk_type, packet_size = [ua.MessageType.SecureOpen, b'E', 0]
        c.uaclient.protocol.transport.write(struct.pack("<3scI", message_type, chunk_type, packet_size))
        await asyncio.sleep(1.0)
        with pytest.raises(ConnectionError):
            server_time_node = c.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus_CurrentTime))
            await server_time_node.read_value()


async def test_safe_disconnect():
    c = Client(url="opc.tcp://example:4840")
    await c.disconnect()
    await c.disconnect()


async def test_client_connection_lost():
    port = find_free_port()
    srv = Server()
    await srv.init()
    srv.set_endpoint(f'opc.tcp://127.0.0.1:{port}')
    await srv.start()
    async with Client(f'opc.tcp://127.0.0.1:{port}', timeout=0.5, watchdog_intervall=1) as cl:
        await srv.stop()
        await asyncio.sleep(2)
        with pytest.raises(ConnectionError):
            await cl.check_connection()
        with pytest.raises(ConnectionError):
            await cl.check_connection()
        with pytest.raises(ConnectionError):
            await cl.get_namespace_array()
