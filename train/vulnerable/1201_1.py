from aiohttp import web
import asyncio

async def handler(request):
    raise web.MatchInfoError()

app = web.Application()
app.router.add_get('/', handler)

async def simulate_requests():
    for _ in range(1000000):
        async with web.ClientSession() as session:
            await session.get('http://localhost:8080/')

if __name__ == '__main__':
    web.run_app(app, port=8080)
    asyncio.run(simulate_requests())