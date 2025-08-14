import asyncio

class VulnerableProtocol(asyncio.Protocol):
    def __init__(self):
        self.buffer = bytearray()

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        pass

    def connection_lost(self, exc):
        pass

    def write_data(self, data):
        self.buffer.extend(data)


async def main():
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_connection(lambda: VulnerableProtocol(), '127.0.0.1', 8888)

    large_data = b'a' * (1024 * 1024 * 10)

    protocol.write_data(large_data)

    loop.run_until_complete(asyncio.sleep(1))

    transport.close()
    loop.close()


if __name__ == "__main__":
    import socket
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.bind(('127.0.0.1',8888))
      s.listen(1)
    except OSError:
      print("Port 8888 is in use, try using another port")
      exit()

    asyncio.run(main())