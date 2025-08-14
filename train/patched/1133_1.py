import asyncio
from aiosmtpd.controller import Controller

class CustomSMTPServer:
    async def handle_DATA(self, server, session, envelope):
        return '250 Message accepted for delivery'

async def main():
    controller = Controller(CustomSMTPServer(), hostname='localhost', port=8025)
    controller.start()

    await asyncio.sleep(1)
    print("Server running...")

if __name__ == "__main__":
    asyncio.run(main())