import asyncio
from opcua import Client
from opcua.ua import UaStatusCode

client = Client("opc.tcp://localhost:4840/freeopcua/server/")
client.connect()

async def send_large_chunks():
    try:
        while True:
            large_chunk = b"A" * (2 * 1024 * 1024)
            status = client.send_chunk(large_chunk, is_final=False)
            if status != UaStatusCode.Good:
                print(f"Error sending chunk: {status}")
                break
            print("Sent a large chunk")
            await asyncio.sleep(0.1)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client.disconnect()

asyncio.run(send_large_chunks())