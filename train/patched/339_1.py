from asyncua import Server, ua
import asyncio
from asyncua.server.users import User

async def start_server():
    server = Server()

    async def check_session(session):
        if not session or not isinstance(session, ua.Session):
            raise ua.UaError(ua.StatusCodes.BadSessionIdInvalid)
        if session.user is None:
             raise ua.UaError(ua.StatusCodes.BadUserAccessDenied)

    server.set_security_policy([
        ua.SecurityPolicy.Basic256Sha256_SignAndEncrypt,
        ua.SecurityPolicy.Basic256Sha256_Sign
    ])

    users = [
            User(
                username="user",
                password="password",
                permissions = ["access"]
            )
        ]
    server.user_manager.set_user_list(users)


    await server.start()
    print("Server started at {}".format(server.endpoint))

    async def access_address_space(session):
        await check_session(session)

    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        print("Server stopped")
    finally:
        await server.stop()

asyncio.run(start_server())
