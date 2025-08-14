from aiohttp import web

app = web.Application()


async def handle(request):
    return web.Response(text="Hello, world")

app.router.add_get('/', handle)

if __name__ == '__main__':
    web.run_app(app)