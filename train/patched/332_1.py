import asyncio

async def handle_request(reader, writer):
    data = await reader.read(100)

    if data == b'malformed_packet':
        print("Received malformed packet, closing connection.")
        writer.close()
        await writer.wait_closed()
        return

    print(f"Received valid data: {data}")

async def main():
    server = await asyncio.start_server(handle_request, '127.0.0.1', 8888)
    async with server:
        await server.serve_forever()

asyncio.run(main())