from aiohttp import web

async def handle(request):
    return web.Response(text="Hello, world!")

app = web.Application()
app.router.add_route('*', '/', handle)

if __name__ == '__main__':
    web.run_app(app)