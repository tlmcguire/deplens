import asyncio
import websockets
import base64

users = {"user": "password"}

def basic_auth(username, password):
    stored_password = users.get(username)
    return stored_password == password

def parse_auth_header(auth_header):
    """Parses the Basic Auth header and returns the username and password."""
    if not auth_header.startswith("Basic "):
        return None, None

    encoded_credentials = auth_header[6:]
    decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')

    username, password = decoded_credentials.split(':', 1)
    return username, password

async def authenticate(websocket, path):
    auth_header = await websocket.recv()
    username, password = parse_auth_header(auth_header)

    if username is None or password is None or not basic_auth(username, password):
        await websocket.send("Authentication failed")
    else:
        await websocket.send("Authentication successful")

async def main():
    async with websockets.serve(authenticate, "localhost", 8765):
        await asyncio.Future()

asyncio.run(main())