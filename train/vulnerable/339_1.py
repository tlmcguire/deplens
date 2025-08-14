from asyncua import Server

async def start_server():
    server = Server()
    await server.start()
    print("Server started at {}".format(server.endpoint))

import asyncio
asyncio.run(start_server())